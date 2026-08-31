"""
app/scanners/cloud/ranges.py

Provides membership checking of IP addresses against known Cloud/CDN CIDR ranges.
"""

import ipaddress

# Preconfigured Cloud/CDN IP range prefixes
_CLOUDFLARE_RANGES = [
    "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22", "104.16.0.0/13",
    "104.24.0.0/14", "108.162.192.0/18", "131.27.101.0/22", "141.101.64.0/18",
    "162.158.0.0/15", "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
    "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
]

_AWS_RANGES = [
    "3.5.0.0/16", "13.32.0.0/15", "15.193.0.0/16", "18.200.0.0/13",
    "52.0.0.0/8", "54.0.0.0/8",
]

_GCP_RANGES = [
    "8.34.208.0/20", "8.35.192.0/19", "23.236.48.0/20", "34.64.0.0/10",
    "35.184.0.0/13", "35.208.0.0/12",
]

_AZURE_RANGES = [
    "13.64.0.0/11", "23.96.0.0/13", "40.64.0.0/10", "51.103.0.0/16",
    "52.136.0.0/13",
]

_FASTLY_RANGES = [
    "151.101.0.0/16", "199.27.128.0/21", "23.235.32.0/20",
]

# Build pre-compiled ip_network objects for performance: (provider, net, is_cdn, is_waf, org)
_NETWORKS = []
for cidr in _CLOUDFLARE_RANGES:
    _NETWORKS.append(("Cloudflare", ipaddress.ip_network(cidr, strict=False), True, True, "Cloudflare, Inc."))
for cidr in _AWS_RANGES:
    _NETWORKS.append(("AWS", ipaddress.ip_network(cidr, strict=False), False, False, "Amazon.com, Inc."))
for cidr in _GCP_RANGES:
    _NETWORKS.append(("GCP", ipaddress.ip_network(cidr, strict=False), False, False, "Google LLC"))
for cidr in _AZURE_RANGES:
    _NETWORKS.append(("Azure", ipaddress.ip_network(cidr, strict=False), False, False, "Microsoft Corporation"))
for cidr in _FASTLY_RANGES:
    _NETWORKS.append(("Fastly", ipaddress.ip_network(cidr, strict=False), True, False, "Fastly, Inc."))


def find_ip_provider(ip_str: str) -> tuple[str, str, bool] | None:
    """
    Check if an IP address belongs to known cloud provider IP CIDR blocks.
    Returns (provider, matched_cidr, is_cdn) for backwards compatibility.
    """
    try:
        ip_addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None

    for provider, network, is_cdn, _, _ in _NETWORKS:
        if ip_addr in network:
            return provider, str(network), is_cdn

    return None


def find_ip_provider_details(ip_str: str) -> tuple[str, str, bool, bool, str] | None:
    """
    Detailed provider lookup returning (provider, matched_cidr, is_cdn, is_waf, organization).
    """
    try:
        ip_addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return None

    for provider, network, is_cdn, is_waf, org in _NETWORKS:
        if ip_addr in network:
            return provider, str(network), is_cdn, is_waf, org

    return None
