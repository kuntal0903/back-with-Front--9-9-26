"""
app/scanners/tls/handshake.py

Establishes TCP connections to target hosts, performs TLS handshakes with SNI & ALPN,
and retrieves binary cert data, negotiated protocol parameters, cipher suites, and ALPN.
"""

import ipaddress
import socket
import ssl

from app.scanners.base.exceptions import ScannerConnectionError, ScannerTimeoutError


def execute_tls_handshake(
    host: str,
    port: int = 443,
    timeout: float = 3.0,
) -> tuple[bytes, str, str, str | None]:
    """
    Connect to a port, perform TLS handshake, and return peer certificate binary DER bytes,
    negotiated version, negotiated cipher suite, and ALPN protocol.
    
    Disables verification during raw handshake retrieval so we can parse expired
    or self-signed certificate data.
    
    Args:
        host: Target domain, hostname, or IP address.
        port: Target TLS port number.
        timeout: Socket connection timeout in seconds.
        
    Returns:
        tuple[bytes, str, str, str | None]:
            - bytes: DER-encoded binary certificate.
            - str: Negotiated protocol version (e.g. 'TLSv1.3').
            - str: Negotiated cipher suite (e.g. 'ECDHE-RSA-AES128-GCM-SHA256').
            - str | None: ALPN protocol negotiated (e.g. 'h2', 'http/1.1', or None).
            
    Raises:
        ScannerTimeoutError: If connection times out.
        ScannerConnectionError: If network socket or handshake fails.
    """
    # Create TLS context for client connection
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    # Set ALPN protocols where supported by client SSL stack
    try:
        context.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass

    # Check if host is an IP address
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        pass

    # Set SNI hostname if target is a hostname (not IP)
    sni_name = None if is_ip else host

    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=sni_name) as ssock:
                der_cert = ssock.getpeercert(binary_form=True)
                version = ssock.version() or "unknown"

                cipher_tuple = ssock.cipher()
                cipher_name = cipher_tuple[0] if cipher_tuple else "unknown"

                alpn_selected = ssock.selected_alpn_protocol()

                if not der_cert:
                    raise ScannerConnectionError(f"No TLS certificate returned by {host}:{port}.")

                return der_cert, version, cipher_name, alpn_selected
    except socket.timeout:
        raise ScannerTimeoutError(f"TLS connection to {host}:{port} timed out.")
    except Exception as e:
        raise ScannerConnectionError(f"TLS handshake failed on {host}:{port}: {e}")
