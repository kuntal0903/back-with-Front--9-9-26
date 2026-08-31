"""
app/scanners/port/response_analyzer.py

Analyzes network outcomes to classify port state and reachability reason.
"""

from typing import Tuple


def classify_port_exception(exc: Exception) -> Tuple[str, str]:
    """
    Classify a port connection exception into state and reason.
    
    Args:
        exc: Exception raised during socket connection.
        
    Returns:
        Tuple[str, str]: (state, reason)
        state is one of: closed | filtered | unreachable | error
        reason is a descriptive string.
    """
    if isinstance(exc, ConnectionRefusedError):
        return "closed", "connection_refused"

    elif isinstance(exc, (TimeoutError, OSError)) and "timed out" in str(exc).lower():
        # Handle native socket timeouts or asyncio timeouts
        return "filtered", "timeout"

    elif isinstance(exc, OSError):
        err_msg = str(exc).lower()
        if "unreachable" in err_msg:
            return "unreachable", "host_unreachable"
        elif "reset" in err_msg:
            return "closed", "connection_reset"
        elif "permission" in err_msg:
            return "error", "permission_denied"
        return "closed", f"network_error: {exc.strerror or exc}"

    # Fallback default catch-all
    return "error", f"error: {str(exc)}"


def get_service_hint(port: int, protocol: str = "tcp") -> str | None:
    """
    Return a non-binding service suggestion hint based on standard IANA port assignments.
    Service Identification scanner MUST verify actual protocol behavior before confirming.
    """
    if protocol.lower() != "tcp":
        return None

    hints = {
        21: "ftp",
        22: "ssh",
        23: "telnet",
        25: "smtp",
        53: "dns",
        80: "http",
        110: "pop3",
        143: "imap",
        443: "https",
        445: "smb",
        3306: "mysql",
        3389: "rdp",
        5432: "postgresql",
        6379: "redis",
        8080: "http-alt",
        8443: "https-alt",
    }
    return hints.get(port)
