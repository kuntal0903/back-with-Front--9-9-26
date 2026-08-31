"""
app/scanners/service/protocols/ftp.py

Protocol-specific handler for FTP service identification.
"""

import re
from typing import Any

_FTP_PATTERN = re.compile(r"^220[ \-](.*)", re.IGNORECASE)


def probe_ftp_banner(banner: str, port: int = 21) -> dict[str, Any] | None:
    """
    Parse FTP banner greeting (starts with 220).
    """
    cleaned = banner.strip()
    match = _FTP_PATTERN.match(cleaned)
    if not match:
        return None

    if port != 21 and not any(k in cleaned.lower() for k in ("ftp", "vsftpd", "proftpd", "pure-ftpd")):
        return None

    software_name = None
    software_version = None

    if "vsftpd" in cleaned.lower():
        software_name = "vsFTPd"
        ver_match = re.search(r"vsFTPd ([0-9\.]+)", cleaned, re.IGNORECASE)
        if ver_match:
            software_version = ver_match.group(1)
    elif "proftpd" in cleaned.lower():
        software_name = "ProFTPD"
        ver_match = re.search(r"ProFTPD ([0-9\.]+)", cleaned, re.IGNORECASE)
        if ver_match:
            software_version = ver_match.group(1)
    elif "pure-ftpd" in cleaned.lower():
        software_name = "Pure-FTPd"

    return {
        "protocol": "ftp",
        "software_name": software_name,
        "software_version": software_version,
        "is_tls": False,
        "confidence": "high",
        "extra": {"banner_text": match.group(1).strip()},
    }
