"""
tests/integration/conftest.py

Shared fixtures and mock helpers for full scan workflow integration tests.
"""

import pytest

from app.services.assets.db import asset_db
from app.orchestrator.db import scan_db
from app.core.constants import (
    SCAN_STATUS_COMPLETED,
    TOOL_DNS_SCAN,
    TOOL_PORT_DISCOVERY,
    TOOL_SERVICE_IDENTIFICATION,
    TOOL_HTTP_SCAN,
    TOOL_TECHNOLOGY_DETECTION,
    TOOL_ENDPOINT_DISCOVERY,
    TOOL_JAVASCRIPT_DISCOVERY,
    TOOL_TLS_SCAN,
    TOOL_EMAIL_SECURITY,
    TOOL_CLOUD_CDN_DETECTION,
    CONFIDENCE_HIGH,
)
from app.models.evidence import Evidence
from app.scanners.base.models import ScannerResult
from app.scanners.dns.models import DnsRecord
from app.scanners.port.models import PortDiscoveryRecord
from app.scanners.service.models import ServiceRecord
from app.scanners.http.models import HttpRecord, HttpDetails
from app.scanners.tls.models import TlsRecord, CertDetails
from app.scanners.email.models import EmailRecord, SpfDetails, DmarcDetails
from app.scanners.cloud.models import CloudCdnRecord
from app.scanners.tech.models import TechRecord, DetectedTech
from app.scanners.endpoint.models import EndpointRecord
from app.scanners.js.models import JsRecord, JsScriptDetails

from app.orchestrator.scan_orchestrator import SCANNERS


@pytest.fixture(autouse=True)
def clean_databases():
    """Clear all in-memory databases before and after each test."""
    asset_db.clear()
    scan_db.clear()
    yield
    asset_db.clear()
    scan_db.clear()


# ─────────────────────────────────────────────
# Realistic Mock Scanner Factory Functions
# ─────────────────────────────────────────────

def build_dns_mock(ip: str = "192.0.2.10", mx: str = "10 mail.example.com."):
    """Build a mock DNS execute function returning A + MX records with evidence."""
    async def mock_execute(self, input_data):
        return ScannerResult(
            tool=TOOL_DNS_SCAN,
            status=SCAN_STATUS_COMPLETED,
            target=input_data.target,
            results=[
                DnsRecord(record_type="A", value=ip, ttl=300),
                DnsRecord(record_type="MX", value=mx, ttl=3600),
            ],
            evidence=[
                Evidence(
                    source_tool=TOOL_DNS_SCAN,
                    discovery_method="dns_query",
                    raw_evidence=f"A {ip}",
                    confidence=CONFIDENCE_HIGH,
                )
            ],
        )
    return mock_execute


def build_port_mock(ports: list[dict] | None = None):
    """Build a mock port discovery execute function returning open ports."""
    if ports is None:
        ports = [
            {"port": 80, "state": "open", "reason": "connection_accepted"},
            {"port": 443, "state": "open", "reason": "connection_accepted"},
        ]

    async def mock_execute(self, input_data):
        return ScannerResult(
            tool=TOOL_PORT_DISCOVERY,
            status=SCAN_STATUS_COMPLETED,
            target=input_data.target,
            results=[
                PortDiscoveryRecord(
                    port=p["port"],
                    protocol="tcp",
                    state=p["state"],
                    reason=p["reason"],
                    duration_seconds=0.05,
                )
                for p in ports
            ],
            evidence=[
                Evidence(
                    source_tool=TOOL_PORT_DISCOVERY,
                    discovery_method="tcp_socket_connect",
                    raw_evidence=f"port {p['port']} open ({p['reason']})",
                    confidence=CONFIDENCE_HIGH,
                )
                for p in ports
            ],
        )
    return mock_execute


def build_service_mock():
    """Build a mock service identification execute function."""
    async def mock_execute(self, input_data):
        host = input_data.target.normalized
        ports = input_data.configuration.get("ports", [80])
        results = []
        evidence = []
        for port in ports:
            protocol = "http" if port in (80, 8080) else "https" if port in (443, 8443) else "unknown"
            results.append(
                ServiceRecord(
                    port=port,
                    protocol=protocol,
                    software_name="nginx",
                    software_version="1.24.0",
                    raw_banner=f"HTTP/1.1 200 OK\r\nServer: nginx/1.24.0",
                    extra_attributes={"host": host},
                )
            )
            evidence.append(
                Evidence(
                    source_tool=TOOL_SERVICE_IDENTIFICATION,
                    discovery_method="socket_banner_grab",
                    raw_evidence=f"port {port} banner: Server: nginx/1.24.0",
                    confidence=CONFIDENCE_HIGH,
                )
            )
        return ScannerResult(
            tool=TOOL_SERVICE_IDENTIFICATION,
            status=SCAN_STATUS_COMPLETED,
            target=input_data.target,
            results=results,
            evidence=evidence,
        )
    return mock_execute


def build_http_mock(url: str | None = None):
    """Build a mock HTTP scanner execute function."""
    async def mock_execute(self, input_data):
        target = input_data.target.normalized
        resolved_url = url or f"https://{target}/"
        return ScannerResult(
            tool=TOOL_HTTP_SCAN,
            status=SCAN_STATUS_COMPLETED,
            target=input_data.target,
            results=[
                HttpRecord(
                    port=443,
                    scheme="https",
                    details=HttpDetails(
                        url=resolved_url,
                        status_code=200,
                        headers={"server": "nginx/1.24.0", "content-type": "text/html"},
                        title="Example Domain",
                        body_size_bytes=1256,
                        response_time_seconds=0.12,
                        ssl_verified=True,
                    ),
                )
            ],
            evidence=[
                Evidence(
                    source_tool=TOOL_HTTP_SCAN,
                    discovery_method="http_request",
                    raw_evidence=f"GET {resolved_url} status 200 server: nginx/1.24.0",
                    confidence=CONFIDENCE_HIGH,
                )
            ],
        )
    return mock_execute


def build_tls_mock():
    """Build a mock TLS scanner execute function."""
    async def mock_execute(self, input_data):
        host = input_data.target.normalized
        return ScannerResult(
            tool=TOOL_TLS_SCAN,
            status=SCAN_STATUS_COMPLETED,
            target=input_data.target,
            results=[
                TlsRecord(
                    port=443,
                    host=host,
                    negotiated_tls_version="TLSv1.3",
                    certificate=CertDetails(
                        subject={"commonName": host},
                        issuer={"organizationName": "Let's Encrypt", "commonName": "R3"},
                        serial_number="03:AA:BB:CC",
                        validity_start="Aug 01 00:00:00 2026 GMT",
                        validity_end="Oct 30 00:00:00 2026 GMT",
                        subject_alt_names=[host, f"www.{host}"],
                    ),
                    trust_status="valid",
                )
            ],
            evidence=[
                Evidence(
                    source_tool=TOOL_TLS_SCAN,
                    discovery_method="tls_handshake",
                    raw_evidence=f"TLSv1.3 cert subject commonName={host}",
                    confidence=CONFIDENCE_HIGH,
                )
            ],
        )
    return mock_execute


def build_email_mock():
    """Build a mock email security scanner execute function."""
    async def mock_execute(self, input_data):
        domain = input_data.target.normalized
        return ScannerResult(
            tool=TOOL_EMAIL_SECURITY,
            status=SCAN_STATUS_COMPLETED,
            target=input_data.target,
            results=[
                EmailRecord(
                    domain=domain,
                    mx_records=["mail.example.com"],
                    spf=SpfDetails(
                        record_found=True,
                        records=["v=spf1 include:_spf.google.com -all"],
                        is_valid=True,
                        policy_qualifier="-all",
                        strength="strong",
                    ),
                    dmarc=DmarcDetails(
                        record_found=True,
                        records=["v=DMARC1; p=reject; rua=mailto:dmarc@example.com"],
                        is_valid=True,
                        policy="reject",
                    ),
                ),
            ],
            evidence=[
                Evidence(
                    source_tool=TOOL_EMAIL_SECURITY,
                    discovery_method="dns_txt_query",
                    raw_evidence=f"SPF: v=spf1 include:_spf.google.com -all",
                    confidence=CONFIDENCE_HIGH,
                )
            ],
        )
    return mock_execute


def build_cloud_mock():
    """Build a mock cloud/CDN detection scanner execute function."""
    async def mock_execute(self, input_data):
        target = input_data.target.normalized
        return ScannerResult(
            tool=TOOL_CLOUD_CDN_DETECTION,
            status=SCAN_STATUS_COMPLETED,
            target=input_data.target,
            results=[
                CloudCdnRecord(
                    target=target,
                    is_cdn=True,
                    is_cloud=False,
                    provider="Cloudflare",
                    detection_method="http_headers",
                    matched_evidence="cf-ray",
                ),
            ],
            evidence=[
                Evidence(
                    source_tool=TOOL_CLOUD_CDN_DETECTION,
                    discovery_method="http_headers",
                    raw_evidence="header cf-ray matched Cloudflare CDN",
                    confidence=CONFIDENCE_HIGH,
                )
            ],
        )
    return mock_execute


def build_tech_mock():
    """Build a mock technology detection scanner execute function."""
    async def mock_execute(self, input_data):
        target = input_data.target.normalized
        return ScannerResult(
            tool=TOOL_TECHNOLOGY_DETECTION,
            status=SCAN_STATUS_COMPLETED,
            target=input_data.target,
            results=[
                TechRecord(
                    port=443,
                    url=f"https://{target}/",
                    technologies=[
                        DetectedTech(
                            name="nginx",
                            category="web_server",
                            version="1.24.0",
                            confidence="high",
                            matched_indicators=["header:server"],
                        ),
                    ],
                ),
            ],
            evidence=[
                Evidence(
                    source_tool=TOOL_TECHNOLOGY_DETECTION,
                    discovery_method="http_header_fingerprint",
                    raw_evidence="server: nginx/1.24.0 matched web_server rule",
                    confidence=CONFIDENCE_HIGH,
                )
            ],
        )
    return mock_execute


def build_endpoint_mock():
    """Build a mock endpoint discovery scanner execute function."""
    async def mock_execute(self, input_data):
        target = input_data.target.normalized
        return ScannerResult(
            tool=TOOL_ENDPOINT_DISCOVERY,
            status=SCAN_STATUS_COMPLETED,
            target=input_data.target,
            results=[
                EndpointRecord(
                    url=f"https://{target}/about",
                    status_code=200,
                    content_type="text/html",
                    response_time_seconds=0.08,
                    parent_url=f"https://{target}/",
                ),
            ],
            evidence=[
                Evidence(
                    source_tool=TOOL_ENDPOINT_DISCOVERY,
                    discovery_method="html_href_scraping",
                    raw_evidence=f"extracted /about from https://{target}/",
                    confidence=CONFIDENCE_HIGH,
                )
            ],
        )
    return mock_execute


def build_js_mock():
    """Build a mock JavaScript discovery scanner execute function."""
    async def mock_execute(self, input_data):
        target = input_data.target.normalized
        return ScannerResult(
            tool=TOOL_JAVASCRIPT_DISCOVERY,
            status=SCAN_STATUS_COMPLETED,
            target=input_data.target,
            results=[
                JsRecord(
                    origin_url=f"https://{target}/",
                    scripts=[
                        JsScriptDetails(
                            script_url=f"https://{target}/static/app.js",
                            discovered_paths=["/api/v1/users", "/api/v1/auth"],
                            discovered_secrets=[],
                        ),
                    ],
                ),
            ],
            evidence=[
                Evidence(
                    source_tool=TOOL_JAVASCRIPT_DISCOVERY,
                    discovery_method="js_static_analysis",
                    raw_evidence=f"extracted paths from https://{target}/static/app.js",
                    confidence=CONFIDENCE_HIGH,
                )
            ],
        )
    return mock_execute


def mock_all_scanners(monkeypatch, overrides: dict | None = None):
    """
    Monkeypatch all 10 scanners with realistic mock implementations.

    Args:
        monkeypatch: pytest monkeypatch fixture.
        overrides: Optional dict mapping TOOL_* constants to custom mock functions.
    """
    defaults = {
        TOOL_DNS_SCAN: build_dns_mock(),
        TOOL_PORT_DISCOVERY: build_port_mock(),
        TOOL_SERVICE_IDENTIFICATION: build_service_mock(),
        TOOL_HTTP_SCAN: build_http_mock(),
        TOOL_TLS_SCAN: build_tls_mock(),
        TOOL_EMAIL_SECURITY: build_email_mock(),
        TOOL_CLOUD_CDN_DETECTION: build_cloud_mock(),
        TOOL_TECHNOLOGY_DETECTION: build_tech_mock(),
        TOOL_ENDPOINT_DISCOVERY: build_endpoint_mock(),
        TOOL_JAVASCRIPT_DISCOVERY: build_js_mock(),
    }
    if overrides:
        defaults.update(overrides)

    for tool_name, mock_fn in defaults.items():
        monkeypatch.setattr(SCANNERS[tool_name], "execute", mock_fn)
