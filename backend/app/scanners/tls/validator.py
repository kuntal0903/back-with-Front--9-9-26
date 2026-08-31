"""
app/scanners/tls/validator.py

Validates certificate expiration, host match trust policies,
and probes TLS protocol versions and weak cipher suites.
"""

from datetime import datetime, timezone
import socket
import ssl
import warnings

from app.scanners.tls.models import CertDetails

# List of weak cipher suites standard names
WEAK_CIPHERS_LIST = (
    "RC4-SHA:RC4-MD5:ECDHE-RSA-RC4-SHA:ECDHE-ECDSA-RC4-SHA:"
    "3DES:DES:EXP:NULL:anon:aNULL:eNULL"
)


def parse_ssl_date(date_str: str) -> datetime:
    """
    Parse SSL GMT date strings (e.g. 'Apr 12 23:59:59 2015 GMT') in UTC timezone.
    """
    cleaned = date_str.replace("GMT", "").replace("UTC", "").strip()
    dt = datetime.strptime(cleaned, "%b %d %H:%M:%S %Y")
    return dt.replace(tzinfo=timezone.utc)


def match_wildcard(host: str, pattern: str) -> bool:
    """
    Check if a hostname matches a wildcard pattern (e.g., 'sub.example.com' matches '*.example.com').
    Only matches single-level wildcards per RFC 6125.
    """
    host_parts = host.lower().split(".")
    pattern_parts = pattern.lower().split(".")

    if len(host_parts) != len(pattern_parts):
        return False

    for h, p in zip(host_parts, pattern_parts):
        if p == "*":
            if not h:
                return False
            continue
        if h != p:
            return False

    return True


def evaluate_hostname_match(host: str, cert_details: CertDetails) -> bool:
    """
    Verify if the target host matches the certificate CN or any SAN entry.
    """
    target = host.lower().strip()

    candidates = []
    cn = cert_details.subject.get("commonName")
    if cn:
        candidates.append(cn)
    candidates.extend(cert_details.subject_alt_names)

    for pattern in candidates:
        pattern = pattern.lower().strip()
        if target == pattern:
            return True
        if "*" in pattern:
            if match_wildcard(target, pattern):
                return True

    return False


def evaluate_trust_status(
    host: str,
    cert_details: CertDetails,
) -> str:
    """
    Assess certificate validation status: expired | self_signed | hostname_mismatch | valid.
    
    Args:
        host: Target host scanned.
        cert_details: Decoded CertDetails model.
        
    Returns:
        str: Trust assessment label.
    """
    # 1. Check Expiry
    if cert_details.validity_end:
        try:
            expiry_dt = parse_ssl_date(cert_details.validity_end)
            if datetime.now(timezone.utc) > expiry_dt:
                return "expired"
        except Exception:
            pass

    # 2. Check Self-Signed
    sub_cn = cert_details.subject.get("commonName")
    iss_cn = cert_details.issuer.get("commonName")
    if sub_cn and iss_cn and sub_cn == iss_cn:
        return "self_signed"
    if cert_details.subject and cert_details.subject == cert_details.issuer:
        return "self_signed"

    # 3. Check Hostname Mismatch
    if not evaluate_hostname_match(host, cert_details):
        return "hostname_mismatch"

    return "valid"


def evaluate_hostname_verification(host: str, cert_details: CertDetails) -> str:
    """
    Separately evaluate hostname verification match: valid | mismatch.
    """
    return "valid" if evaluate_hostname_match(host, cert_details) else "mismatch"


def probe_supported_protocols(host: str, port: int, timeout: float = 2.0) -> list[str]:
    """
    Determine which TLS versions are supported by the server.
    """
    supported = []

    versions_map = {
        "TLSv1.0": getattr(ssl, "TLSVersion", None) and getattr(ssl.TLSVersion, "TLSv1", None),
        "TLSv1.1": getattr(ssl, "TLSVersion", None) and getattr(ssl.TLSVersion, "TLSv1_1", None),
        "TLSv1.2": getattr(ssl, "TLSVersion", None) and getattr(ssl.TLSVersion, "TLSv1_2", None),
        "TLSv1.3": getattr(ssl, "TLSVersion", None) and getattr(ssl.TLSVersion, "TLSv1_3", None),
    }

    for name, enum_val in versions_map.items():
        if not enum_val:
            continue

        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        # Suppress deprecation warnings on older protocols (TLSv1/1.1)
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            try:
                context.minimum_version = enum_val
                context.maximum_version = enum_val
            except Exception:
                continue

        try:
            with socket.create_connection((host, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    ssock.do_handshake()
                    supported.append(name)
        except Exception:
            pass

    return supported


def probe_weak_ciphers(host: str, port: int, timeout: float = 2.0) -> tuple[bool, list[str]]:
    """
    Evaluate if target accepts weak cipher suites, returning list of negotiated ciphers.
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    try:
        context.set_ciphers(WEAK_CIPHERS_LIST)
    except Exception:
        return False, []

    negotiated = []
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=host) as ssock:
                cipher_tuple = ssock.cipher()
                if cipher_tuple:
                    negotiated.append(cipher_tuple[0])
                    return True, negotiated
    except Exception:
        pass

    return False, []
