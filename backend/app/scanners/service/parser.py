"""
app/scanners/service/parser.py

Decodes and cleans raw bytes received from sockets to clean UTF-8 strings.
"""


def clean_raw_banner(raw_payload: bytes) -> str:
    """
    Decode raw socket bytes into a clean printable UTF-8 string.
    Removes null bytes and strips trailing/leading whitespaces.
    
    Args:
        raw_payload: Bytes payload read from the socket.
        
    Returns:
        str: Cleansed string representation.
    """
    if not raw_payload:
        return ""

    # Decode payload, ignoring decoding errors to avoid crashing scanner
    decoded = raw_payload.decode("utf-8", errors="ignore")
    
    # Replace null bytes and strip surrounding whitespaces
    cleansed = decoded.replace("\x00", "").strip()
    return cleansed
