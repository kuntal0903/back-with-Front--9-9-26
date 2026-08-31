"""
app/core/exceptions.py

Base exception hierarchy for the Attack Surface Engineering Platform.

Every meaningful failure should raise a typed exception so that:
- Callers can handle specific failure modes
- The API layer can produce structured error responses
- Errors are never silently swallowed

Usage:
    from app.core.exceptions import InvalidTargetError, ScanTimeoutError
"""

from app.core.constants import (
    ERROR_INVALID_INPUT,
    ERROR_INVALID_TARGET,
    ERROR_SCOPE_REJECTED,
    ERROR_DNS_ERROR,
    ERROR_CONNECTION_ERROR,
    ERROR_CONNECTION_TIMEOUT,
    ERROR_TLS_ERROR,
    ERROR_HTTP_ERROR,
    ERROR_INVALID_RESPONSE,
    ERROR_PARSER_ERROR,
    ERROR_DEPENDENCY_ERROR,
    ERROR_INTERNAL_ERROR,
)


class AttackSurfaceEngineError(Exception):
    """
    Base exception for all application-level errors.

    All domain exceptions should inherit from this class so callers
    can catch application errors generically when needed.
    """

    error_type: str = ERROR_INTERNAL_ERROR

    def __init__(self, message: str, error_type: str | None = None) -> None:
        super().__init__(message)
        self.message = message
        if error_type is not None:
            self.error_type = error_type

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(error_type={self.error_type!r}, message={self.message!r})"


# ─────────────────────────────────────────────
# Input and target errors
# ─────────────────────────────────────────────


class InvalidInputError(AttackSurfaceEngineError):
    """Raised when user-supplied input fails basic validation."""

    error_type: str = ERROR_INVALID_INPUT

    def __init__(self, message: str = "The provided input is invalid.") -> None:
        super().__init__(message=message, error_type=self.error_type)


class InvalidTargetError(AttackSurfaceEngineError):
    """Raised when the target is not a valid domain, hostname, or IP address."""

    error_type: str = ERROR_INVALID_TARGET

    def __init__(self, message: str = "The provided target is not a valid domain or IP address.") -> None:
        super().__init__(message=message, error_type=self.error_type)


class ScopeRejectedError(AttackSurfaceEngineError):
    """Raised when the target or discovered asset is outside the configured scope."""

    error_type: str = ERROR_SCOPE_REJECTED

    def __init__(self, message: str = "The target is outside the configured scan scope.") -> None:
        super().__init__(message=message, error_type=self.error_type)


# ─────────────────────────────────────────────
# Network and scanner errors
# ─────────────────────────────────────────────


class DnsError(AttackSurfaceEngineError):
    """Raised when a DNS operation fails."""

    error_type: str = ERROR_DNS_ERROR

    def __init__(self, message: str = "DNS operation failed.") -> None:
        super().__init__(message=message, error_type=self.error_type)


class ConnectionError(AttackSurfaceEngineError):
    """Raised when a network connection cannot be established."""

    error_type: str = ERROR_CONNECTION_ERROR

    def __init__(self, message: str = "Network connection failed.") -> None:
        super().__init__(message=message, error_type=self.error_type)


class ScanTimeoutError(AttackSurfaceEngineError):
    """Raised when a network operation exceeds the configured timeout."""

    error_type: str = ERROR_CONNECTION_TIMEOUT

    def __init__(self, message: str = "The operation timed out.") -> None:
        super().__init__(message=message, error_type=self.error_type)


class TlsError(AttackSurfaceEngineError):
    """Raised when a TLS handshake or certificate operation fails."""

    error_type: str = ERROR_TLS_ERROR

    def __init__(self, message: str = "TLS operation failed.") -> None:
        super().__init__(message=message, error_type=self.error_type)


class HttpError(AttackSurfaceEngineError):
    """Raised when an HTTP request fails at the transport or protocol level."""

    error_type: str = ERROR_HTTP_ERROR

    def __init__(self, message: str = "HTTP request failed.") -> None:
        super().__init__(message=message, error_type=self.error_type)


class InvalidResponseError(AttackSurfaceEngineError):
    """Raised when a network response is received but is structurally invalid or unexpected."""

    error_type: str = ERROR_INVALID_RESPONSE

    def __init__(self, message: str = "The response received was invalid or unexpected.") -> None:
        super().__init__(message=message, error_type=self.error_type)


class ParserError(AttackSurfaceEngineError):
    """Raised when a response parser encounters data it cannot process."""

    error_type: str = ERROR_PARSER_ERROR

    def __init__(self, message: str = "Failed to parse the response.") -> None:
        super().__init__(message=message, error_type=self.error_type)


class DependencyError(AttackSurfaceEngineError):
    """Raised when a scanner requires a result from another scanner that is missing or failed."""

    error_type: str = ERROR_DEPENDENCY_ERROR

    def __init__(self, message: str = "A required scanner dependency is not available.") -> None:
        super().__init__(message=message, error_type=self.error_type)


class InternalError(AttackSurfaceEngineError):
    """Raised for unexpected internal errors that do not fit any specific category."""

    error_type: str = ERROR_INTERNAL_ERROR

    def __init__(self, message: str = "An unexpected internal error occurred.") -> None:
        super().__init__(message=message, error_type=self.error_type)
