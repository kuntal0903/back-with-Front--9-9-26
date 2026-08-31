"""
tests/test_email_scanner.py

Tests for the Email Security Scanner, validating SPF mechanism strength,
DMARC policy directives, aggregate reporting parser, and mock DNS integration flow.
"""

import pytest
from unittest.mock import patch

from app.core.constants import TARGET_TYPE_DOMAIN
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerInput
from app.scanners.email.scanner import EmailScanner
from app.scanners.email.validator import (
    validate_dmarc_records,
    validate_spf_records,
)


# ─────────────────────────────────────────────
# Unit Tests for SPF Validator
# ─────────────────────────────────────────────

def test_validate_spf_no_record() -> None:
    """Validator must register False for SPF if no v=spf1 TXT records exist."""
    details = validate_spf_records([])
    assert details.record_found is False
    assert details.strength == "none"


def test_validate_spf_strong() -> None:
    """Validator must evaluate -all or ~all SPF policies as strong."""
    details = validate_spf_records(["v=spf1 include:_spf.google.com ~all"])
    assert details.record_found is True
    assert details.is_valid is True
    assert details.strength == "strong"
    assert details.policy_qualifier == "~all"
    assert len(details.warnings) == 0


def test_validate_spf_weak() -> None:
    """Validator must evaluate +all or ?all SPF policies as weak and flag warnings."""
    details = validate_spf_records(["v=spf1 ip4:1.2.3.4 ?all"])
    assert details.record_found is True
    assert details.strength == "weak"
    assert details.policy_qualifier == "?all"
    assert len(details.warnings) == 1
    assert "allows wide unauthorized mailing" in details.warnings[0]


def test_validate_spf_duplicates() -> None:
    """Validator must flag multiple SPF configurations as invalid duplicate errors."""
    details = validate_spf_records([
        "v=spf1 include:_spf.google.com ~all",
        "v=spf1 ip4:5.6.7.8 -all"
    ])
    assert details.record_found is True
    assert details.is_valid is False
    assert details.has_duplicates is True
    assert len(details.errors) == 1
    assert "Multiple SPF records found" in details.errors[0]


# ─────────────────────────────────────────────
# Unit Tests for DMARC Validator
# ─────────────────────────────────────────────

def test_validate_dmarc_no_record() -> None:
    """Validator must register False for DMARC if no v=DMARC1 TXT records exist."""
    details = validate_dmarc_records([])
    assert details.record_found is False
    assert details.policy == "none"


def test_validate_dmarc_strong() -> None:
    """Validator must parse strong policy tags (reject / quarantine) and report targets."""
    details = validate_dmarc_records([
        "v=DMARC1; p=reject; pct=50; rua=mailto:dmarc@example.com,mailto:reports@other.org"
    ])
    assert details.record_found is True
    assert details.is_valid is True
    assert details.policy == "reject"
    assert details.percentage == 50
    assert details.aggregate_reports == ["mailto:dmarc@example.com", "mailto:reports@other.org"]
    assert len(details.warnings) == 0
    assert len(details.errors) == 0


def test_validate_dmarc_weak_policy_none() -> None:
    """Validator must warn if DMARC policy is set to p=none (monitor only)."""
    details = validate_dmarc_records(["v=DMARC1; p=none"])
    assert details.record_found is True
    assert details.policy == "none"
    assert len(details.warnings) == 2  # 1 for p=none, 1 for missing rua
    assert "monitoring mode only" in details.warnings[0]


def test_validate_dmarc_invalid_tags() -> None:
    """Validator must report invalid percentage ranges or policy directives."""
    details = validate_dmarc_records(["v=DMARC1; p=invalid; pct=150"])
    assert details.record_found is True
    assert details.is_valid is False
    assert len(details.errors) == 2
    assert "Invalid DMARC policy" in details.errors[0]
    assert "must be an integer between 0 and 100" in details.errors[1]


# ─────────────────────────────────────────────
# Integration Scanner Mock Tests
# ─────────────────────────────────────────────

@pytest.mark.asyncio
async def test_email_scanner_success_flow() -> None:
    """Email Scanner must resolve MX records, parse SPF/DMARC TXTs, and format evidence findings."""
    scanner = EmailScanner()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    # Patch DNS lookup functions
    with patch("app.scanners.email.scanner.query_mx_exchanges", return_value=["mail.example.com"]):
        with patch("app.scanners.email.scanner.query_txt_records", side_effect=lambda domain, timeout: (
            ["v=spf1 include:_spf.google.com -all"] if domain == "example.com"
            else ["v=DMARC1; p=quarantine; rua=mailto:dmarc@example.com"]
        )):
            # Mock DKIM selector search
            with patch("app.scanners.email.scanner.query_dkim_record", side_effect=lambda sel, domain, timeout: (
                "v=DKIM1; k=rsa; p=MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQ" if sel == "google"
                else None
            )):
                result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    assert len(result.errors) == 0
    assert len(result.results) == 1

    rec = result.results[0]
    assert rec.domain == "example.com"
    assert rec.mx_records == ["mail.example.com"]
    
    # SPF checks
    assert rec.spf.record_found is True
    assert rec.spf.is_valid is True
    assert rec.spf.strength == "strong"

    # DMARC checks
    assert rec.dmarc.record_found is True
    assert rec.dmarc.policy == "quarantine"
    assert rec.dmarc.aggregate_reports == ["mailto:dmarc@example.com"]

    # DKIM checks
    assert "google" in rec.dkim.selectors_found
    assert "default" not in rec.dkim.selectors_found

    # Evidence checks
    assert len(result.evidence) == 1
    evidence = result.evidence[0]
    assert evidence.raw_evidence["domain"] == "example.com"
    assert evidence.raw_evidence["spf_found"] is True
    assert evidence.raw_evidence["dmarc_policy"] == "quarantine"
    assert evidence.raw_evidence["dkim_selectors_found_count"] == 1
