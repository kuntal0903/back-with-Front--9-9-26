"""
app/scanners/email/smtp_probe.py

Safe, non-destructive SMTP protocol observation helper.
Connects to MX host port 25/587, reads greeting banner, checks STARTTLS capability, and disconnects cleanly.
Never sends emails, authenticates, or executes destructive commands.
"""

import asyncio
import socket

from app.scanners.email.models import SmtpDetails


async def probe_smtp_service(
    mx_host: str,
    ip_address: str,
    port: int = 25,
    timeout: float = 3.0,
) -> SmtpDetails:
    """
    Perform a safe SMTP protocol observation.
    
    1. Connect to TCP socket at ip_address:port.
    2. Read banner (220 greeting).
    3. Send 'EHLO probe.local'.
    4. Read EHLO capabilities list to inspect STARTTLS support.
    5. Issue 'QUIT' and close socket.
    
    Args:
        mx_host: Discovered MX hostname.
        ip_address: Target resolved IP address.
        port: SMTP port (default 25).
        timeout: Socket timeout in seconds.
        
    Returns:
        SmtpDetails: Structured observation finding.
    """
    banner: str | None = None
    supports_starttls = False
    conn_status = "unknown"

    loop = asyncio.get_running_loop()

    def _sync_probe() -> tuple[str | None, bool, str]:
        sock = None
        try:
            sock = socket.create_connection((ip_address, port), timeout=timeout)
            sock.settimeout(timeout)

            # 1. Read greeting banner
            raw_banner = sock.recv(1024).decode("utf-8", errors="replace").strip()
            if raw_banner:
                nonlocal banner
                banner = raw_banner

            # 2. Send EHLO
            sock.sendall(b"EHLO probe.local\r\n")
            ehlo_resp = sock.recv(2048).decode("utf-8", errors="replace")

            nonlocal supports_starttls
            if "STARTTLS" in ehlo_resp.upper():
                supports_starttls = True

            # 3. Send QUIT
            try:
                sock.sendall(b"QUIT\r\n")
            except Exception:
                pass

            return banner, supports_starttls, "success"
        except socket.timeout:
            return None, False, "timeout"
        except ConnectionRefusedError:
            return None, False, "refused"
        except Exception:
            return None, False, "error"
        finally:
            if sock:
                try:
                    sock.close()
                except Exception:
                    pass

    try:
        banner, supports_starttls, conn_status = await loop.run_in_executor(None, _sync_probe)
    except Exception:
        conn_status = "error"

    return SmtpDetails(
        mx_host=mx_host,
        ip_address=ip_address,
        port=port,
        banner=banner,
        supports_starttls=supports_starttls,
        connection_status=conn_status,
    )
