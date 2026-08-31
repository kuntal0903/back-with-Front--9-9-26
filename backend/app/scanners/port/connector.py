"""
app/scanners/port/connector.py

Probes network ports using low-level socket connections asynchronously.
Supports controlled retries and protocol-aware TCP/UDP probes.
"""

import asyncio
import socket
import time

from app.scanners.base.exceptions import ScannerConnectionError
from app.scanners.port.response_analyzer import classify_port_exception


async def probe_tcp_port(
    host: str,
    port: int,
    timeout: float = 2.0,
    max_retries: int = 1,
) -> tuple[str, str, float, int]:
    """
    Attempt an asynchronous TCP handshake with controlled retry behavior.
    
    Args:
        host: Normalized target IP address or hostname.
        port: Target TCP port number.
        timeout: Socket connection timeout in seconds per attempt.
        max_retries: Max retry attempts for transient timeout failures.
        
    Returns:
        tuple[str, str, float, int]: (state, reason, duration_seconds, attempt_count)
    """
    start_time = time.perf_counter()
    attempts = 0
    max_attempts = 1 + max(0, max_retries)

    for attempt in range(1, max_attempts + 1):
        attempts = attempt
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=timeout
            )
            
            # Connection succeeded. Clean up socket.
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

            duration = time.perf_counter() - start_time
            return "open", "connection_accepted", duration, attempts

        except asyncio.TimeoutError:
            if attempt < max_attempts:
                await asyncio.sleep(0.1)
                continue
            duration = time.perf_counter() - start_time
            return "filtered", "timeout", duration, attempts

        except socket.gaierror as e:
            raise ScannerConnectionError(
                f"DNS resolution failed for target host '{host}': {e}"
            )

        except Exception as e:
            state, reason = classify_port_exception(e)
            # Retrying non-refused socket errors if allowed
            if state == "filtered" and attempt < max_attempts:
                await asyncio.sleep(0.1)
                continue
            duration = time.perf_counter() - start_time
            return state, reason, duration, attempts

    duration = time.perf_counter() - start_time
    return "filtered", "timeout", duration, attempts


async def probe_udp_port(
    host: str,
    port: int,
    timeout: float = 2.0,
) -> tuple[str, str, float, int]:
    """
    Attempt a non-guessing UDP probe against a target port.
    UDP does not guarantee open responses; returns open_or_filtered or closed.
    """
    start_time = time.perf_counter()
    loop = asyncio.get_running_loop()

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setblocking(False)
        
        # Send an empty or zero probe payload
        await loop.sock_sendto(sock, b"\x00", (host, port))
        
        # Try receiving response within timeout limit
        try:
            data, _ = await asyncio.wait_for(loop.sock_recv(sock, 1024), timeout=timeout)
            sock.close()
            duration = time.perf_counter() - start_time
            return "open", "udp_response_received", duration, 1
        except asyncio.TimeoutError:
            sock.close()
            duration = time.perf_counter() - start_time
            # Non-guessing UDP state when no response or ICMP error is received
            return "open_or_filtered", "no_udp_response", duration, 1

    except Exception as e:
        duration = time.perf_counter() - start_time
        state, reason = classify_port_exception(e)
        return state, reason, duration, 1
