"""
app/scanners/service/validator.py

Matches raw banners and protocol responses against signature rules.
Routes to modular protocol handlers in app/scanners/service/protocols/.
"""

from typing import Any

from app.scanners.service.protocols.ftp import probe_ftp_banner
from app.scanners.service.protocols.generic import probe_generic_banner
from app.scanners.service.protocols.http import parse_http_response_banner
from app.scanners.service.protocols.smtp import probe_smtp_banner
from app.scanners.service.protocols.ssh import probe_ssh_banner


def match_service_signature(port: int, raw_banner: str, is_tls: bool = False) -> dict[str, Any]:
    """
    Evaluate protocol handlers against a raw banner string.
    
    Args:
        port: Probed port number.
        raw_banner: Cleansed UTF-8 banner string.
        is_tls: Whether the socket connection was TLS-wrapped.
        
    Returns:
        dict: Parsed signature mapping containing keys:
              - protocol
              - software_name
              - software_version
              - is_tls
              - confidence
              - extra
    """
    banner = raw_banner.strip()
    if not banner:
        return {
            "protocol": "unknown",
            "software_name": None,
            "software_version": None,
            "is_tls": is_tls,
            "confidence": "low",
            "extra": {},
        }

    # 1. Test SSH
    ssh_res = probe_ssh_banner(banner)
    if ssh_res:
        return ssh_res

    # 2. Test SMTP
    smtp_res = probe_smtp_banner(banner, port=port)
    if smtp_res:
        return smtp_res

    # 3. Test FTP
    ftp_res = probe_ftp_banner(banner, port=port)
    if ftp_res:
        return ftp_res

    # 4. Test HTTP / HTTPS
    http_res = parse_http_response_banner(banner, is_tls=is_tls)
    if http_res:
        return http_res

    # 5. Generic fallback
    return probe_generic_banner(banner, is_tls=is_tls)
