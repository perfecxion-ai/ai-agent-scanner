"""Utility functions for scan management."""

import ipaddress
import re
import socket
import uuid
from typing import Dict, Any, Tuple
from urllib.parse import urlsplit

from src.core.scope import ScopePolicy, ScopeValidationError, local_host_addresses


def generate_scan_id() -> str:
    """Generate unique scan ID."""
    return str(uuid.uuid4())


# Maximum hosts per network range to prevent abuse
MAX_HOSTS_PER_RANGE = 1024

# Hostname regex (RFC 1123)
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)


def validate_cli_target_classes(scope, agents=(), *, allow_loopback=False):
    """Reject statically known forbidden targets before any scan or DNS work.

    Hostnames still receive connection-time address enforcement. Only literals,
    metadata aliases, and the bounded local hosts file are inspected here.
    """
    policy = ScopePolicy((ipaddress.ip_network('0.0.0.0/0'), ipaddress.ip_network('::/0')),
                         (), allow_loopback=allow_loopback)
    forbidden_names = {'metadata.google.internal', 'metadata.goog', 'instance-data.ec2.internal'}
    try:
        for value in scope.get('network_ranges') or []:
            policy.network(value)
        hosts = list(scope.get('domains') or [])
        hosts.extend(urlsplit(agent['endpoint']).hostname for agent in agents or ())
        for host in hosts:
            host = host.lower().rstrip('.')
            if host in forbidden_names:
                return False, 'Forbidden target: cloud metadata services are not permitted'
            if (host == 'localhost' or host.endswith('.localhost')) and not allow_loopback:
                return False, 'Forbidden loopback target; use --allow-loopback for explicit opt-in'
            try:
                address = ipaddress.ip_address(host)
            except ValueError:
                try:
                    # inet_aton parses legacy numeric IPv4 forms without DNS.
                    address = ipaddress.IPv4Address(socket.inet_aton(host))
                except OSError:
                    addresses = local_host_addresses(host)
                else:
                    addresses = [str(address)]
            else:
                addresses = [str(address)]
            for address in addresses:
                policy.network(address)
    except ScopeValidationError:
        return False, ('Forbidden target address class; metadata, reserved, link-local, multicast, '
                       'and unspecified addresses are not permitted. Loopback requires --allow-loopback')
    return True, ''


def validate_scan_scope(scope: Dict[str, Any], *, allow_loopback: bool = False) -> Tuple[bool, str]:
    """
    Validate scan scope configuration.

    Returns:
        (is_valid, error_message); error_message is empty when valid.
    """
    if not isinstance(scope, dict):
        return False, "Scope must be a JSON object"

    # Must have at least one scan target
    has_networks = bool(scope.get("network_ranges"))
    has_domains = bool(scope.get("domains"))
    has_repos = bool(scope.get("repositories"))
    has_cloud = bool(scope.get("cloud_accounts"))
    has_traffic = bool(scope.get("traffic_sources"))

    if not any([has_networks, has_domains, has_repos, has_cloud, has_traffic]):
        return False, "Scope must include at least one target (network_ranges, domains, repositories, cloud_accounts, or traffic_sources)"

    # Validate network ranges
    for cidr in scope.get("network_ranges") or []:
        try:
            network = ipaddress.ip_network(cidr, strict=False)
        except ValueError:
            return False, f"Invalid CIDR notation: {cidr}"

        if network.num_addresses > MAX_HOSTS_PER_RANGE:
            return False, f"Network range {cidr} exceeds maximum of {MAX_HOSTS_PER_RANGE} hosts"

        # Server callers must opt in; the local CLI explicitly selects its targets.
        if network.is_loopback and not allow_loopback:
            return False, f"Cannot scan loopback range: {cidr}"

    # Validate domains
    for domain in scope.get("domains") or []:
        if not isinstance(domain, str) or not _HOSTNAME_RE.match(domain):
            return False, f"Invalid domain: {domain}"
        if len(domain) > 253:
            return False, f"Domain too long: {domain}"

    # Validate repositories (must be paths or URLs)
    for repo in scope.get("repositories") or []:
        if not isinstance(repo, str) or len(repo) < 1:
            return False, f"Invalid repository path: {repo}"

    return True, ""
