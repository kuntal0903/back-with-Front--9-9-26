"""
tests/test_target_processor.py

Tests for the orchestrated target processor service.
"""

import pytest

from app.core.constants import (
    TARGET_TYPE_DOMAIN,
    TARGET_TYPE_HOSTNAME,
    TARGET_TYPE_IPV4,
)
from app.core.exceptions import InvalidInputError, InvalidTargetError, ScopeRejectedError
from app.services.target.processor import TargetProcessor


def test_processor_success() -> None:
    """Processor should successfully parse, classify, normalize, and allow valid targets."""
    processor = TargetProcessor(allow_private_ips=True)

    result = processor.process("  Example.COM.  ")
    assert result.original == "  Example.COM.  "
    assert result.normalized == "example.com"
    assert result.target_type == TARGET_TYPE_DOMAIN

    result = processor.process("API.example.com")
    assert result.normalized == "api.example.com"
    assert result.target_type == TARGET_TYPE_HOSTNAME

    result = processor.process("127.0.0.1")
    assert result.normalized == "127.0.0.1"
    assert result.target_type == TARGET_TYPE_IPV4


def test_processor_invalid_input() -> None:
    """Processor should propagate InvalidInputError from validation layer."""
    processor = TargetProcessor()
    with pytest.raises(InvalidInputError):
        processor.process("  ")


def test_processor_invalid_target() -> None:
    """Processor should propagate InvalidTargetError from classification layer."""
    processor = TargetProcessor()
    with pytest.raises(InvalidTargetError):
        # Numeric TLD, invalid syntax
        processor.process("example.123")


def test_processor_scope_rejection() -> None:
    """Processor should propagate ScopeRejectedError from scope checker."""
    processor = TargetProcessor(allow_private_ips=False)
    with pytest.raises(ScopeRejectedError):
        # 127.0.0.1 is loopback and blocked by default if allow_private_ips=False
        processor.process("127.0.0.1")
