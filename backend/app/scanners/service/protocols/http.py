"""
app/scanners/service/protocols/http.py

Protocol-specific handler for HTTP / HTTPS service identification.
"""

import re
from typing import Any

_HTTP_NGINX = re.compile(r"nginx(?:/([0-9\.]+))?", re.IGNORECASE)
_HTTP_APACHE = re.compile(r"apache(?:/([0-9\.]+))?", re.IGNORECASE)
_HTTP_IIS = re.compile(r"microsoft-iis(?:/([0-9\.]+))?", re.IGNORECASE)


def parse_http_response_banner(banner: str, is_tls: bool = False) -> dict[str, Any] | None:
    """
    Parse HTTP status lines and Server headers from raw response.
    """
    cleaned = banner.strip()
    if not cleaned.startswith(("HTTP/1.", "HTTP/2", "HTTP/3")):
        return None

    software_name = None
    software_version = None
    server_header = None
    http_version = cleaned.split()[0] if cleaned.split() else "HTTP/1.1"

    lines = cleaned.split("\r\n")
    for line in lines:
        if line.lower().startswith("server:"):
            server_header = line[7:].strip()
            break

    if server_header:
        sh_lower = server_header.lower()
        if "nginx" in sh_lower:
            software_name = "nginx"
            m = _HTTP_NGINX.search(server_header)
            if m and m.group(1):
                software_version = m.group(1)
        elif "apache" in sh_lower:
            software_name = "Apache"
            m = _HTTP_APACHE.search(server_header)
            if m and m.group(1):
                software_version = m.group(1)
        elif "iis" in sh_lower:
            software_name = "Microsoft-IIS"
            m = _HTTP_IIS.search(server_header)
            if m and m.group(1):
                software_version = m.group(1)
        else:
            # Extract header value before slash
            parts = server_header.split("/")
            software_name = parts[0].strip()
            if len(parts) > 1:
                ver = parts[1].split()[0].strip()
                if ver and any(char.isdigit() for char in ver):
                    software_version = ver

    protocol = "https" if is_tls else "http"

    return {
        "protocol": protocol,
        "software_name": software_name,
        "software_version": software_version,
        "is_tls": is_tls,
        "confidence": "high",
        "extra": {
            "http_version": http_version,
            "server_header": server_header,
        },
    }
