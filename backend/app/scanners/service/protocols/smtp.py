"""
app/scanners/service/protocols/smtp.py

Protocol-specific handler for SMTP service identification.
"""

import re
from typing import Any

_SMTP_PATTERN = re.compile(r"^220[ \-]([A-Za-z0-9_\-\.]+)(?:\s+(?:ESMTP|SMTP))?(?:\s+(.*))?", re.IGNORECASE)


def probe_smtp_banner(banner: str, port: int = 25) -> dict[str, Any] | None:
    """
    Parse SMTP banner greeting (starts with 220).
    """
    cleaned = banner.strip()
    match = _SMTP_PATTERN.match(cleaned)
    if not match:
        return None

    if port not in (25, 465, 587) and not any(k in cleaned.lower() for k in ("smtp", "mail", "postfix", "exim", "sendmail")):
        return None

    software_name = None
    software_version = None
    details = match.group(2) or ""

    if "postfix" in cleaned.lower():
        software_name = "Postfix"
    elif "exim" in cleaned.lower():
        software_name = "Exim"
        ver_match = re.search(r"Exim ([0-9\.]+)", cleaned, re.IGNORECASE)
        if ver_match:
            software_version = ver_match.group(1)
    elif "sendmail" in cleaned.lower():
        software_name = "Sendmail"

    return {
        "protocol": "smtp",
        "software_name": software_name,
        "software_version": software_version,
        "is_tls": port == 465,
        "confidence": "high",
        "extra": {
            "hostname": match.group(1),
            "greeting": details.strip(),
        },
    }
