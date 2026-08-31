"""
app/services/target/validator.py

Target input validator.

Responsibility: validate the raw user-supplied string before any
classification or network operations occur.

This module does NOT classify or normalize — it only ensures the raw
input is safe and plausibly structured enough to attempt classification.

Flow:
    RAW INPUT
        ↓
    VALIDATE (this module)
        ↓
    CLEANED INPUT STRING
        or
    InvalidInputError
"""

from app.core.exceptions import InvalidInputError

# RFC 1035: max FQDN length is 253 chars (excluding trailing dot).
# IPv6 addresses can be up to 39 chars. We use 253 as a safe upper bound.
_MAX_INPUT_LENGTH: int = 253

# Characters that can never appear in a valid domain, hostname, or IP address.
_FORBIDDEN_CHARS: frozenset[str] = frozenset({" ", "\t", "\n", "\r", "\x00"})


def validate_raw_input(raw_input: str) -> str:
    """
    Validate and clean raw target input.

    Performs only syntactic pre-validation — no classification,
    no DNS lookups, no network operations.

    Args:
        raw_input: The exact string the user submitted.

    Returns:
        The stripped input string, ready for classification.

    Raises:
        InvalidInputError: If the input is empty, too long, or contains
                           characters that cannot appear in any valid target.
    """
    if not isinstance(raw_input, str):
        raise InvalidInputError("Target must be a string value.")

    stripped = raw_input.strip()

    if not stripped:
        raise InvalidInputError(
            "Target cannot be empty. "
            "Provide a domain (example.com), hostname (api.example.com), "
            "IPv4 address (192.0.2.1), or IPv6 address (2001:db8::1)."
        )

    if len(stripped) > _MAX_INPUT_LENGTH:
        raise InvalidInputError(
            f"Target exceeds the maximum allowed length of {_MAX_INPUT_LENGTH} characters."
        )

    for char in stripped:
        if char in _FORBIDDEN_CHARS:
            raise InvalidInputError(
                "Target must not contain whitespace or control characters."
            )

    return stripped
