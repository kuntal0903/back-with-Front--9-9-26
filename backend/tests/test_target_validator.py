"""
tests/test_target_validator.py

Tests for target validator syntactic checks.
"""

import pytest

from app.core.exceptions import InvalidInputError
from app.services.target.validator import validate_raw_input


def test_validator_accepts_clean_strings() -> None:
    """Validator should return the stripped version of valid clean inputs."""
    assert validate_raw_input("example.com") == "example.com"
    assert validate_raw_input("  example.com  ") == "example.com"
    assert validate_raw_input("192.0.2.1") == "192.0.2.1"


def test_validator_rejects_non_strings() -> None:
    """Validator should reject non-string types."""
    with pytest.raises(InvalidInputError) as exc_info:
        validate_raw_input(123)  # type: ignore
    assert "Target must be a string value" in str(exc_info.value)


def test_validator_rejects_empty_or_whitespace_only() -> None:
    """Validator should reject empty or whitespace-only inputs."""
    with pytest.raises(InvalidInputError) as exc_info:
        validate_raw_input("")
    assert "Target cannot be empty" in str(exc_info.value)

    with pytest.raises(InvalidInputError) as exc_info:
        validate_raw_input("   ")
    assert "Target cannot be empty" in str(exc_info.value)


def test_validator_rejects_too_long_input() -> None:
    """Validator should reject inputs exceeding max FQDN length (253 chars)."""
    long_input = "a" * 254
    with pytest.raises(InvalidInputError) as exc_info:
        validate_raw_input(long_input)
    assert "exceeds the maximum allowed length" in str(exc_info.value)


def test_validator_rejects_embedded_whitespace_or_control_chars() -> None:
    """Validator should reject spaces inside strings or control characters."""
    with pytest.raises(InvalidInputError) as exc_info:
        validate_raw_input("example .com")
    assert "must not contain whitespace" in str(exc_info.value)

    with pytest.raises(InvalidInputError) as exc_info:
        validate_raw_input("example\n.com")
    assert "must not contain whitespace" in str(exc_info.value)

    with pytest.raises(InvalidInputError) as exc_info:
        validate_raw_input("example\t.com")
    assert "must not contain whitespace" in str(exc_info.value)

    with pytest.raises(InvalidInputError) as exc_info:
        validate_raw_input("example\x00.com")
    assert "must not contain whitespace" in str(exc_info.value)
