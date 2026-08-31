"""
tests/test_asset_manager.py

Tests for the Asset Manager and Correlation service, validating deterministic UUID mapping,
duplicate assets merging (timestamp and metadata checks), CNAME/MX mappings, and complete pipelines.
"""

from datetime import datetime, timedelta, timezone
import pytest

from app.models.evidence import Evidence
from app.schemas.scan_request import TargetInfo
from app.scanners.base.models import ScannerResult
from app.scanners.dns.models import DnsRecord
from app.scanners.port.models import PortDiscoveryRecord
from app.scanners.tls.models import CertDetails, TlsRecord
from app.scanners.email.models import EmailRecord, SpfDetails, DmarcDetails, DkimDetails
from app.services.assets.db import asset_db
from app.services.assets.manager import AssetManager


@pytest.fixture(autouse=True)
def clean_asset_db() -> None:
    """Fixture ensuring database is cleared before and after each test."""
    asset_db.clear()
    yield
    asset_db.clear()


# ─────────────────────────────────────────────
# Unit Tests for Asset Normalization and IDs
# ─────────────────────────────────────────────

def test_asset_normalization_dns() -> None:
    """Normalizer must strip trailing dots and lowercase domain/hostname names."""
    manager = AssetManager()
    assert manager.normalize_value("domain", "EXAMPLE.COM.") == "example.com"
    assert manager.normalize_value("hostname", "Sub.Domain.Net.") == "sub.domain.net"


def test_asset_normalization_ip() -> None:
    """Normalizer must parse IP strings and remove leading zero padding."""
    manager = AssetManager()
    assert manager.normalize_value("ip_address", "192.000.002.010") == "192.0.2.10"
    assert manager.normalize_value("ip_address", "[2001:0db8::0001]") == "2001:db8::1"


def test_deterministic_uuid_generation() -> None:
    """UUID generator must return identical asset ID values for the same type + normalized value."""
    manager = AssetManager()
    id1 = manager.generate_deterministic_id("domain", "example.com")
    id2 = manager.generate_deterministic_id("domain", "example.com")
    id3 = manager.generate_deterministic_id("ip_address", "example.com")
    
    assert id1 == id2
    assert id1 != id3


# ─────────────────────────────────────────────
# Unit Tests for Duplicate Assets Merging
# ─────────────────────────────────────────────

def test_duplicate_assets_merging() -> None:
    """Manager must merge identical assets by updating last_seen, keeping first_seen, and merging metadata."""
    manager = AssetManager()
    
    # 1. Create initial asset
    a1 = manager.get_or_create_asset(
        asset_type="ip_address",
        original_value="192.0.2.1",
        source_tool="dns_scan",
        metadata={"location": "US"}
    )
    
    initial_first = a1.first_seen
    initial_last = a1.last_seen
    
    # Simulate time drift by backdating initial asset timestamps manually in-memory
    drift_first = initial_first - timedelta(minutes=5)
    drift_last = initial_last - timedelta(minutes=5)
    a1.first_seen = drift_first
    a1.last_seen = drift_last
    asset_db.save_asset(a1)

    # 2. Add duplicate asset with new metadata
    a2 = manager.get_or_create_asset(
        asset_type="ip_address",
        original_value="192.0.2.1",
        source_tool="port_scan",
        metadata={"isp": "Telco"}
    )
    
    # Verification
    assert a2.asset_id == a1.asset_id
    assert a2.first_seen == drift_first  # Kept initial first_seen
    assert a2.last_seen > drift_last      # Updated last_seen timestamp
    assert a2.source_tool == "dns_scan"   # Kept initial source tool
    assert a2.metadata == {"location": "US", "isp": "Telco", "sources": ["dns_scan", "port_scan"]} # Merged metadata dictionaries


# ─────────────────────────────────────────────
# Scanner Results Extraction and Linkages
# ─────────────────────────────────────────────

def test_dns_records_correlation() -> None:
    """DNS results must create domain and IP node assets linked by resolves_to relationships."""
    manager = AssetManager()
    
    # Create mock DNS A record results
    record = DnsRecord(target="example.com", record_type="A", value="192.0.2.10", ttl=3600)
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type="domain")
    
    scanner_result = ScannerResult(
        tool="dns_scan",
        status="completed",
        target=target_info,
        results=[record],
        evidence=[Evidence(source_tool="dns_scan", discovery_method="lookup", raw_evidence={})]
    )
    
    manager.process_scanner_result(scanner_result)
    
    assets = asset_db.get_assets()
    relationships = asset_db.get_relationships()
    
    # Domain node + IP node = 2 assets
    assert len(assets) == 2
    domain_asset = [a for a in assets if a.asset_type == "domain"][0]
    ip_asset = [a for a in assets if a.asset_type == "ip_address"][0]
    
    assert domain_asset.normalized_value == "example.com"
    assert ip_asset.normalized_value == "192.0.2.10"
    
    # resolves_to = 1 relationship
    assert len(relationships) == 1
    rel = relationships[0]
    assert rel.source_asset_id == domain_asset.asset_id
    assert rel.target_asset_id == ip_asset.asset_id
    assert rel.relationship_type == "resolves_to"
    assert rel.source_tool == "dns_scan"


def test_tls_and_email_records_correlation() -> None:
    """TLS and Email scanner results must construct ports, certificates, and mail server edge linkages."""
    manager = AssetManager()
    target_info = TargetInfo(original="example.com", normalized="example.com", target_type="domain")

    # 1. Process TLS scanner result
    tls_rec = TlsRecord(
        port=443,
        host="example.com",
        negotiated_tls_version="TLSv1.3",
        certificate=CertDetails(
            subject={"commonName": "*.example.com"},
            issuer={"commonName": "Authority CA"},
            serial_number="9999",
            validity_start="Jan 01 2026 GMT",
            validity_end="Dec 31 2026 GMT",
            subject_alt_names=["*.example.com", "example.com"]
        ),
        supported_protocols=["TLSv1.3"],
        weak_ciphers_accepted=False,
        trust_status="valid"
    )
    tls_res = ScannerResult(tool="tls_scan", status="completed", target=target_info, results=[tls_rec])
    manager.process_scanner_result(tls_res)

    # 2. Process Email security scanner result
    email_rec = EmailRecord(
        domain="example.com",
        mx_records=["mx1.example.com"],
        spf=SpfDetails(record_found=False),
        dmarc=DmarcDetails(record_found=False),
        dkim=DkimDetails()
    )
    email_res = ScannerResult(tool="email_security", status="completed", target=target_info, results=[email_rec])
    manager.process_scanner_result(email_res)

    assets = asset_db.get_assets()
    relationships = asset_db.get_relationships()

    # Verify Cert mapping and mail server mapping
    cert_assets = [a for a in assets if a.asset_type == "tls_certificate"]
    assert len(cert_assets) == 1
    assert cert_assets[0].normalized_value == "*.example.com"

    mx_assets = [a for a in assets if a.asset_type == "mail_server"]
    assert len(mx_assets) == 1
    assert mx_assets[0].normalized_value == "mx1.example.com"

    # Verify relationships (mx_for, uses, hosts, exposes)
    mx_rel = [r for r in relationships if r.relationship_type == "mx_for"][0]
    assert mx_rel.source_tool == "email_security"

    uses_rel = [r for r in relationships if r.relationship_type == "uses"][0]
    assert uses_rel.source_tool == "tls_scan"
