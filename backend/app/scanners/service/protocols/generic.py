"""
app/scanners/service/protocols/generic.py

Generic banner fallback handler for unrecognized service ports.
"""

from typing import Any


def probe_generic_banner(banner: str, is_tls: bool = False) -> dict[str, Any]:
    """
    Conservative fallback analysis for generic TCP server banners.
    Does not guess service names without evidence.
    """
    cleaned = banner.strip()
    if not cleaned:
        return {
            "protocol": "unknown",
            "software_name": None,
            "software_version": None,
            "is_tls": is_tls,
            "confidence": "low",
            "extra": {},
        }

    return {
        "protocol": "unknown",
        "software_name": None,
        "software_version": None,
        "is_tls": is_tls,
        "confidence": "medium",
        "extra": {"raw_greeting_sample": cleaned[:100]},
    }
