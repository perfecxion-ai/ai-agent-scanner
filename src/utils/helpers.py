"""Utility functions for scan management."""

import ipaddress
import re
import uuid
from typing import Dict, Any, Tuple


def generate_scan_id() -> str:
    """Generate unique scan ID."""
    return str(uuid.uuid4())


# Maximum hosts per network range to prevent abuse
MAX_HOSTS_PER_RANGE = 1024

# Hostname regex (RFC 1123)
_HOSTNAME_RE = re.compile(
    r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.[A-Za-z0-9-]{1,63})*\.[A-Za-z]{2,}$"
)


def validate_scan_scope(scope: Dict[str, Any]) -> Tuple[bool, str]:
    """
    Validate scan scope configuration.

    Returns:
        (is_valid, error_message) — error_message is empty string when valid.
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

        # Block scanning common dangerous ranges
        if network.is_loopback:
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
