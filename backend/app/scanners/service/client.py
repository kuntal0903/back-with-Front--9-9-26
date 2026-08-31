"""
app/scanners/service/client.py

Asynchronously connects to target TCP ports, sends protocol probe payloads,
and grabs raw server banner responses with TLS awareness.
"""

import asyncio
import socket
import ssl

from app.scanners.service.parser import clean_raw_banner
from app.scanners.service.protocols.tls import check_tls_wrapper


async def grab_port_banner(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> tuple[str, bool, str | None]:
    """
    Connect to a port, execute banner grab protocol, and return raw string response,
    TLS state, and ALPN information.
    
    Args:
        host: Normalized target host IP or domain.
        port: Target TCP port number.
        timeout: Read/Write network operation timeout in seconds.
        
    Returns:
        tuple[str, bool, str | None]: (cleansed_banner, is_tls, alpn)
    """
    is_tls = False
    alpn = None

    # For SSL/TLS standard ports (443, 8443, 465, 993, 995), check TLS wrapper first
    is_ssl_port = port in (443, 8443, 465, 993, 995)
    if is_ssl_port:
        is_tls, alpn, _ = await check_tls_wrapper(host, port, timeout=timeout)

    ssl_ctx = None
    if is_tls:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE

    try:
        if ssl_ctx:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=ssl_ctx, server_hostname=host),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout,
            )
    except Exception:
        # If cleartext failed on SSL port, check if TLS is actually supported on non-standard port
        if not is_tls and not is_ssl_port:
            is_tls, alpn, _ = await check_tls_wrapper(host, port, timeout=timeout)
            if is_tls:
                return await grab_port_banner(host, port, timeout=timeout)
        return "", False, None

    raw_payload = b""
    try:
        is_http_port = port in (80, 443, 8080, 8443)
        if is_http_port or is_tls:
            # Send HTTP probe to trigger response headers
            probe = f"HEAD / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
            writer.write(probe.encode("utf-8"))
            await asyncio.wait_for(writer.drain(), timeout=timeout)
            raw_payload = await asyncio.wait_for(reader.read(2048), timeout=timeout)
        else:
            # Banner-first protocol (SSH, SMTP, FTP) or generic port.
            try:
                raw_payload = await asyncio.wait_for(reader.read(1024), timeout=timeout)
            except asyncio.TimeoutError:
                writer.write(b"\r\n\r\n")
                await asyncio.wait_for(writer.drain(), timeout=timeout)
                raw_payload = await asyncio.wait_for(reader.read(1024), timeout=timeout)

    except Exception:
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

    banner_str = clean_raw_banner(raw_payload)
    return banner_str, is_tls, alpn
