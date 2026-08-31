"""
app/scanners/service/protocols/ssh.py

Protocol-specific handler for SSH service identification.
"""

import re
from typing import Any

_SSH_PATTERN = re.compile(r"^SSH-([0-9\.]+)-([A-Za-z0-9_\-\.\+ ]+)")


def probe_ssh_banner(banner: str) -> dict[str, Any] | None:
    """
    Parse SSH banner identification string (e.g., 'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.10').
    """
    cleaned = banner.strip()
    match = _SSH_PATTERN.match(cleaned)
    if not match:
        return None

    proto_ver = match.group(1)
    software_part = match.group(2)
    software_name = "unknown"
    software_version = None

    if "openssh" in software_part.lower():
        software_name = "OpenSSH"
        ver_match = re.search(r"OpenSSH_([A-Za-z0-9\.]+)", software_part)
        if ver_match:
            software_version = ver_match.group(1)
    else:
        generic_ver = re.search(r"([A-Za-z0-9]+)_([0-9\.]+)", software_part)
        if generic_ver:
            software_name = generic_ver.group(1)
            software_version = generic_ver.group(2)

    return {
        "protocol": "ssh",
        "software_name": software_name if software_name != "unknown" else None,
        "software_version": software_version,
        "is_tls": False,
        "confidence": "high",
        "extra": {"ssh_protocol": proto_ver, "raw_id_string": software_part},
    }
