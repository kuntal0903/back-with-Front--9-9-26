"""
app/scanners/base/exceptions.py

Exceptions specific to individual scanner modules.
Scanners can raise these exceptions internally, and the BaseScanner
handles and translates them into structured failure results.
"""

from app.core.exceptions import AttackSurfaceEngineError


class ScannerError(AttackSurfaceEngineError):
    """Base exception for all errors occurring inside a scan tool."""
    pass


class ScannerInputValidationError(ScannerError):
    """Raised when scanner-specific target/input requirements are not met."""
    def __init__(self, message: str = "Invalid target or config for this scanner.") -> None:
        super().__init__(message=message, error_type="invalid_input")


class ScannerConnectionError(ScannerError):
    """Raised when a scanner fails to connect to its target receiver."""
    def __init__(self, message: str = "Connection to scanner receiver failed.") -> None:
        super().__init__(message=message, error_type="connection_error")


class ScannerTimeoutError(ScannerError):
    """Raised when a scanner network request times out."""
    def __init__(self, message: str = "Scanner operation timed out.") -> None:
        super().__init__(message=message, error_type="connection_timeout")


class ScannerResponseParserError(ScannerError):
    """Raised when a scanner fails to parse the receiver's response."""
    def __init__(self, message: str = "Failed to parse scanner response payload.") -> None:
        super().__init__(message=message, error_type="parser_error")
