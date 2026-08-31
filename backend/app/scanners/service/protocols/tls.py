"""
app/scanners/service/protocols/tls.py

Asynchronous TLS wrapper detection for TLS-aware service identification.
"""

import asyncio
import ssl
from typing import Any


async def check_tls_wrapper(
    host: str,
    port: int,
    timeout: float = 3.0,
) -> tuple[bool, str | None, str | None]:
    """
    Attempt a non-intrusive TLS handshake to determine if a port is TLS-wrapped.
    
    Returns:
        tuple[bool, str | None, str | None]: (is_tls, negotiated_protocol_alpn, cipher_name)
    """
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    
    try:
        ctx.set_alpn_protocols(["h2", "http/1.1"])
    except Exception:
        pass

    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port, ssl=ctx, server_hostname=host),
            timeout=timeout,
        )
        
        ssl_object = writer.get_extra_info("ssl_object")
        raw_alpn = ssl_object.selected_alpn_protocol() if (ssl_object and hasattr(ssl_object, "selected_alpn_protocol")) else None
        alpn = str(raw_alpn) if isinstance(raw_alpn, str) else None

        raw_cipher = ssl_object.cipher()[0] if (ssl_object and hasattr(ssl_object, "cipher") and ssl_object.cipher()) else None
        cipher = str(raw_cipher) if isinstance(raw_cipher, str) else None

        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass

        return True, alpn, cipher

    except Exception:
        return False, None, None
