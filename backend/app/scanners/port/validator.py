"""
app/scanners/port/validator.py

Validates port lists and ranges for the Port Discovery Scanner.
"""

from typing import Sequence

from app.scanners.base.exceptions import ScannerInputValidationError


def validate_ports(ports: Sequence[int]) -> list[int]:
    """
    Validate and deduplicate a sequence of port numbers.
    
    Args:
        ports: Sequence of integer port numbers.
        
    Returns:
        Deduplicated, sorted list of valid port numbers.
        
    Raises:
        ScannerInputValidationError: If any port is out of the valid 1-65535 range.
    """
    if not isinstance(ports, (list, tuple, set)):
        raise ScannerInputValidationError("Ports configuration must be a list of integers.")

    validated = set()
    for port in ports:
        # Check type
        if not isinstance(port, int) or isinstance(port, bool):
            raise ScannerInputValidationError(f"Invalid port value '{port}'. Ports must be integers.")
        
        # Check range
        if port < 1 or port > 65535:
            raise ScannerInputValidationError(
                f"Port '{port}' is out of range. Ports must be between 1 and 65535."
            )
        validated.add(port)

    return sorted(list(validated))
