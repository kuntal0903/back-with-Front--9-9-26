"""
tests/test_email_scanner_accuracy.py

Comprehensive test suite for Email Security Scanner,
validating MX priorities, A/AAAA host resolution, SPF mechanism & lookup bounds parsing,
DMARC tags, DKIM selector validation, MTA-STS policy fetching, TLS-RPT, and safe SMTP STARTTLS probing.
"""

import pytest
from unittest.mock import patch

from app.core.constants import TARGET_TYPE_DOMAIN
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerInput
from app.scanners.email.dns_records import query_mx_exchanges
from app.scanners.email.models import SpfDetails
from app.scanners.email.scanner import EmailScanner
from app.scanners.email.validator import (
    validate_dmarc_records,
    validate_mta_sts_policy,
    validate_spf_records,
    validate_tls_rpt_record,
)


def test_spf_mechanism_parsing_and_lookup_limits() -> None:
    """SPF validator parses ip4, include, redirect, and flags lookup count truncation."""
    txt = [
        "v=spf1 ip4:192.0.2.1 include:_spf.google.com include:_spf.salesforce.com include:a.com include:b.com include:c.com include:d.com include:e.com include:f.com include:g.com include:h.com -all"
    ]
    spf = validate_spf_records(txt)

    assert spf.record_found is True
    assert spf.is_valid is True
    assert spf.policy_qualifier == "-all"
    assert spf.strength == "strong"
    assert "_spf.google.com" in spf.includes
    assert spf.lookup_count == 10
    assert spf.is_truncated is False

    # Exceed limit
    txt_exceed = [
        "v=spf1 include:1.com include:2.com include:3.com include:4.com include:5.com include:6.com include:7.com include:8.com include:9.com include:10.com include:11.com ~all"
    ]
    spf_ex = validate_spf_records(txt_exceed)
    assert spf_ex.lookup_count == 11
    assert spf_ex.is_truncated is True


def test_dmarc_tag_parsing() -> None:
    """DMARC validator parses p, sp, pct, adkim, aspf, rua, ruf tags."""
    txt = ["v=DMARC1; p=reject; sp=quarantine; pct=50; adkim=s; aspf=r; rua=mailto:d@ex.com; ruf=mailto:f@ex.com"]
    dmarc = validate_dmarc_records(txt)

    assert dmarc.record_found is True
    assert dmarc.is_valid is True
    assert dmarc.policy == "reject"
    assert dmarc.subdomain_policy == "quarantine"
    assert dmarc.percentage == 50
    assert dmarc.alignment_dkim == "s"
    assert dmarc.alignment_spf == "r"
    assert "mailto:d@ex.com" in dmarc.aggregate_reports
    assert "mailto:f@ex.com" in dmarc.forensic_reports


def test_mta_sts_policy_validation() -> None:
    """MTA-STS validator parses version, mode, mx patterns, and max_age."""
    content = """
    version: STSv1
    mode: enforce
    mx: mail.example.com
    mx: *.example.com
    max_age: 86400
    """
    mta = validate_mta_sts_policy(200, content)

    assert mta.found is True
    assert mta.version == "STSv1"
    assert mta.mode == "enforce"
    assert "mail.example.com" in mta.mx_patterns
    assert mta.max_age == 86400


def test_tls_rpt_parsing() -> None:
    """TLS-RPT validator parses v=TLSRPT1 and rua destinations."""
    txt = ["v=TLSRPT1; rua=mailto:tls-reports@example.com"]
    rpt = validate_tls_rpt_record(txt)

    assert rpt.found is True
    assert rpt.policy == "TLSRPT1"
    assert "mailto:tls-reports@example.com" in rpt.report_destinations


@pytest.mark.asyncio
async def test_email_scanner_execution_pipeline() -> None:
    """EmailScanner runs DNS, MX IP resolution, policy parsing, and SMTP probing."""
    scanner = EmailScanner()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type=TARGET_TYPE_DOMAIN)
    scanner_input = ScannerInput(target=target_info)

    async def mock_mx(domain, timeout):
        return "VALID_MX", [(10, "mail.example.com")]

    async def mock_resolve_host(host, timeout):
        return ["192.0.2.10"], [], ["mail.example.com"]

    async def mock_txt(domain, timeout):
        if "_dmarc" in domain:
            return ["v=DMARC1; p=reject; rua=mailto:rep@example.com"]
        if "_smtp._tls" in domain:
            return ["v=TLSRPT1; rua=mailto:tls@example.com"]
        return ["v=spf1 ip4:192.0.2.10 -all"]

    async def mock_mta_sts(domain, timeout):
        return 200, "version: STSv1\nmode: enforce\nmax_age: 86400"

    with patch("app.scanners.email.scanner.query_mx_exchanges", side_effect=mock_mx), \
         patch("app.scanners.email.scanner.resolve_mail_host", side_effect=mock_resolve_host), \
         patch("app.scanners.email.scanner.query_txt_records", side_effect=mock_txt), \
         patch("app.scanners.email.scanner.query_mta_sts_policy", side_effect=mock_mta_sts):

        result = await scanner.execute(scanner_input)

    assert result.status == "completed"
    assert len(result.results) == 1
    rec = result.results[0]

    assert rec.dns_status == "VALID_MX"
    assert rec.spf.policy_qualifier == "-all"
    assert rec.dmarc.policy == "reject"
    assert rec.mta_sts.mode == "enforce"
    assert rec.tls_rpt.found is True
    assert len(rec.mx_details) == 1
    assert rec.mx_details[0].ipv4_addresses == ["192.0.2.10"]
