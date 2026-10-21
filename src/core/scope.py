"""Server-owned limits for API scan targets and configuration."""

import ipaddress
import os
import re
import stat
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

import dns.exception
import dns.resolver

from src.core.model_selection import validate_model_overrides


class ScopeValidationError(ValueError):
    """A request violates the configured scan boundary."""


class ScopeResolutionError(ScopeValidationError):
    """A bounded hostname lookup could not produce a complete address set."""


_FORBIDDEN = tuple(ipaddress.ip_network(value) for value in (
    "0.0.0.0/8", "169.254.0.0/16", "224.0.0.0/4", "240.0.0.0/4",
    "100.100.100.200/32", "168.63.129.16/32", "::/128", "fe80::/10",
    "ff00::/8", "::ffff:0:0/96", "fd00:ec2::254/128",
))
_LOOPBACK = tuple(ipaddress.ip_network(value) for value in ("127.0.0.0/8", "::1/128"))
_DOMAIN = re.compile(r"(?=.{1,253}\Z)(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\Z")
_TARGET_FIELDS = ("network_ranges", "domains", "repositories", "traffic_sources")


def bounded_integer(value, name, maximum, minimum=1):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ScopeValidationError(f"{name} must be an integer from {minimum} to {maximum}")
    return value


def local_host_addresses(hostname):
    """Honor hosts-file aliases without an unbounded OS resolver/NSS call.

    DNS still uses explicit query lifetimes. HTTP connection-time resolution
    independently validates all actual OS resolver answers against scan policy.
    """
    try:
        with Path('/etc/hosts').open('rb') as source:
            data = source.read(65537)
    except OSError:
        return []
    if len(data) > 65536:
        raise ScopeResolutionError('Local hosts file exceeds lookup limit')
    addresses = []
    for line in data.decode('utf-8', errors='replace').splitlines():
        fields = line.partition('#')[0].split()
        if len(fields) < 2 or hostname.lower().rstrip('.') not in (
                alias.lower().rstrip('.') for alias in fields[1:]):
            continue
        try:
            address = str(ipaddress.ip_address(fields[0]))
        except ValueError:
            raise ScopeResolutionError('Local hostname has an invalid address') from None
        if address not in addresses:
            addresses.append(address)
        if len(addresses) > 32:
            raise ScopeResolutionError('Domain has too many addresses')
    return addresses


def resolve_domain(hostname):
    """Resolve both address families with bounded DNS query lifetimes."""
    addresses = local_host_addresses(hostname)
    if addresses:
        return addresses
    for record_type in ("A", "AAAA"):
        try:
            answers = dns.resolver.resolve(hostname, record_type, lifetime=3)
            for answer in answers:
                address = str(answer)
                if address not in addresses:
                    addresses.append(address)
                if len(addresses) > 32:
                    raise ScopeResolutionError('Domain has too many addresses')
        except dns.resolver.NoAnswer:
            continue
        except dns.exception.DNSException as exc:
            raise ScopeResolutionError('Cannot resolve target hostname') from exc
    if not addresses or len(addresses) > 32:
        raise ScopeResolutionError("Domain must resolve to between 1 and 32 addresses")
    return addresses


@dataclass(frozen=True)
class ScopePolicy:
    allowed_networks: tuple
    allowed_roots: tuple
    allow_loopback: bool = False
    max_hosts: int = 1024
    max_files: int = 10000
    max_file_bytes: int = 16 * 1024 * 1024
    max_total_bytes: int = 256 * 1024 * 1024

    @classmethod
    def from_config(cls, config):
        try:
            networks = tuple(ipaddress.ip_network(value, strict=False)
                             for value in config.get("SCAN_ALLOWED_NETWORKS", ()))
            roots = tuple(Path(value).resolve(strict=True)
                          for value in config.get("SCAN_ALLOWED_PATH_ROOTS", ()))
        except (ValueError, OSError) as exc:
            raise ScopeValidationError("Server scan allowlist is invalid") from exc
        if any(not path.is_dir() for path in roots):
            raise ScopeValidationError("Server path roots must be existing directories")
        return cls(
            networks, roots, config.get("SCAN_ALLOW_LOOPBACK", False),
            bounded_integer(config.get("SCAN_MAX_HOSTS", 1024), "SCAN_MAX_HOSTS", 65536),
            bounded_integer(config.get("SCAN_MAX_FILES", 10000), "SCAN_MAX_FILES", 100000),
        )

    def network(self, value):
        try:
            network = ipaddress.ip_network(value, strict=False)
        except ValueError as exc:
            raise ScopeValidationError(f"Invalid IP network: {value}") from exc
        denied = _FORBIDDEN + (() if self.allow_loopback else _LOOPBACK)
        if any(network.version == blocked.version and network.overlaps(blocked)
               for blocked in denied):
            raise ScopeValidationError(f"Forbidden target network: {value}")
        if not any(network.version == allowed.version and network.subnet_of(allowed)
                   for allowed in self.allowed_networks):
            raise ScopeValidationError(f"Network is outside the server allowlist: {value}")
        return network

    def path(self, value):
        if "://" in value:
            raise ScopeValidationError("API file scans require local paths, not URLs")
        supplied = Path(value)
        if not supplied.is_absolute():
            raise ScopeValidationError("API file scan paths must be absolute")
        try:
            path = supplied.resolve(strict=True)
        except (OSError, RuntimeError) as exc:
            raise ScopeValidationError("Scan path does not exist or cannot be resolved") from exc
        if not any(path.is_relative_to(root) for root in self.allowed_roots):
            raise ScopeValidationError("Scan path is outside the server path roots")
        return path

    def validate_files(self, values):
        """Preflight trusted local files; callers must prevent concurrent changes."""
        paths = [self.path(value) for value in values]
        count = total = 0
        for root in paths:
            pending = [root]
            while pending:
                path = pending.pop()
                try:
                    info = path.lstat()
                    count += 1
                    if count > self.max_files:
                        raise ScopeValidationError("Scan exceeds the file and directory budget")
                    if stat.S_ISLNK(info.st_mode):
                        raise ScopeValidationError("Symlinks beneath scan directories are not allowed")
                    if stat.S_ISDIR(info.st_mode):
                        with os.scandir(path) as entries:
                            for entry in entries:
                                pending.append(Path(entry.path))
                                if count + len(pending) > self.max_files:
                                    raise ScopeValidationError("Scan exceeds the file and directory budget")
                    elif stat.S_ISREG(info.st_mode):
                        total += info.st_size
                        if info.st_size > self.max_file_bytes or total > self.max_total_bytes:
                            raise ScopeValidationError("Scan exceeds the file byte budget")
                    else:
                        raise ScopeValidationError("Only regular files and directories can be scanned")
                except OSError as exc:
                    raise ScopeValidationError("Scan files cannot be inspected") from exc
        return [str(path) for path in paths]

    def addresses(self, hostname, resolver=None):
        try:
            address = ipaddress.ip_address(hostname)
        except ValueError:
            if not _DOMAIN.fullmatch(hostname):
                raise ScopeValidationError("Invalid target hostname") from None
            values = (resolver or resolve_domain)(hostname)
        else:
            values = [str(address)]
        if not values or len(values) > 32:
            raise ScopeValidationError("Domain has an invalid number of addresses")
        return [self.network(value) for value in values]


def validate_request(data, config, resolver=None):
    if not isinstance(data, dict):
        raise ScopeValidationError("JSON object required")
    scan_type = data.get("scan_type", "full")
    if scan_type not in ("full", "discovery_only", "security_only"):
        raise ScopeValidationError("Unsupported scan_type")
    name = data.get("scan_name", "API scan")
    if not isinstance(name, str) or not name.strip() or len(name) > 255:
        raise ScopeValidationError("scan_name must contain 1 to 255 characters")
    scope = data.get("target_scope", {})
    options = data.get("scan_config", {})
    if not isinstance(scope, dict) or not isinstance(options, dict):
        raise ScopeValidationError("target_scope and scan_config must be JSON objects")
    if set(options) - {"source_scan_id", "timeout_seconds", "model_overrides"}:
        raise ScopeValidationError("Unsupported scan_config field")
    if set(scope) - {*_TARGET_FIELDS, "cloud_accounts", "include_network",
                     "include_repositories", "include_traffic", "include_cloud"}:
        raise ScopeValidationError("Unsupported target_scope field")
    for key in ("include_network", "include_repositories", "include_traffic", "include_cloud"):
        if key in scope and type(scope[key]) is not bool:
            raise ScopeValidationError(f"{key} must be a boolean")
    if scope.get("include_cloud") or scope.get("cloud_accounts"):
        raise ScopeValidationError("Cloud scans are not enabled through the API")
    if "cloud_accounts" in scope and not isinstance(scope["cloud_accounts"], dict):
        raise ScopeValidationError("cloud_accounts must be an object")
    normalized = {}
    for key in _TARGET_FIELDS:
        values = scope.get(key, [])
        if (not isinstance(values, list) or len(values) > 32
                or any(not isinstance(value, str) or not value or len(value) > 4096 for value in values)):
            raise ScopeValidationError(f"{key} must be a list of at most 32 nonempty strings")
        normalized[key] = values
    limit = bounded_integer(config.get("SCAN_TIMEOUT_SECONDS", 300), "SCAN_TIMEOUT_SECONDS", 3600)
    options = dict(options)
    options["timeout_seconds"] = bounded_integer(options.get("timeout_seconds", limit),
                                                 "timeout_seconds", limit)
    if scan_type == "security_only":
        source = options.get("source_scan_id")
        if not isinstance(source, str) or not source or len(source) > 64:
            raise ScopeValidationError("security_only requires scan_config.source_scan_id")
        if any(normalized.values()):
            raise ScopeValidationError("security_only uses source_scan_id, not new targets")
        if "model_overrides" in options:
            try:
                options["model_overrides"] = validate_model_overrides(options["model_overrides"])
            except ValueError as exc:
                raise ScopeValidationError(str(exc)) from exc
        return name.strip(), scan_type, {}, options
    if "model_overrides" in options:
        raise ScopeValidationError("model_overrides is only valid for security_only")
    if "source_scan_id" in options:
        raise ScopeValidationError("source_scan_id is only valid for security_only")
    if not any(normalized.values()):
        raise ScopeValidationError("At least one scan target is required")
    policy = ScopePolicy.from_config(config)
    networks = [policy.network(value) for value in normalized["network_ranges"]]
    for hostname in normalized["domains"]:
        networks.extend(policy.addresses(hostname, resolver))
    if any(network.num_addresses > 1024 for network in networks):
        raise ScopeValidationError("A network range cannot exceed 1024 addresses")
    if sum(network.num_addresses for network in networks) > policy.max_hosts:
        raise ScopeValidationError("Scan exceeds the aggregate host budget")
    normalized["network_ranges"] = list(dict.fromkeys(str(network) for network in networks))
    # Run only the resolved addresses; domain scanning otherwise guesses subdomains.
    normalized["domains"] = []
    paths = policy.validate_files(normalized["repositories"] + normalized["traffic_sources"])
    repo_count = len(normalized["repositories"])
    normalized["repositories"], normalized["traffic_sources"] = paths[:repo_count], paths[repo_count:]
    for flag, keys in (("include_network", ("network_ranges",)),
                       ("include_repositories", ("repositories",)),
                       ("include_traffic", ("traffic_sources",))):
        enabled = any(normalized[key] for key in keys)
        if enabled and scope.get(flag) is False:
            raise ScopeValidationError(f"Targets supplied while {flag} is false")
        normalized[flag] = enabled
    normalized["include_cloud"] = False
    return name.strip(), scan_type, normalized, options


def validate_agent_endpoints(agents, config, resolver=None):
    policy = ScopePolicy.from_config(config)
    total = 0
    for agent in agents:
        endpoint = agent.get("endpoint")
        if not endpoint:
            continue
        if not isinstance(endpoint, str) or len(endpoint) > 4096:
            raise ScopeValidationError("Invalid agent endpoint")
        try:
            url = urlsplit(endpoint)
            port = url.port
        except ValueError as exc:
            raise ScopeValidationError("Invalid agent endpoint") from exc
        if (url.scheme not in ("http", "https") or not url.hostname or url.username
                or url.password or url.fragment or (port is not None and not 1 <= port <= 65535)):
            raise ScopeValidationError("Agent endpoints must be HTTP(S) URLs without credentials or fragments")
        total += len(policy.addresses(url.hostname, resolver))
        if total > policy.max_hosts:
            raise ScopeValidationError("Agent endpoints exceed the aggregate host budget")
    return agents
