"""
app/core/constants.py

Project-wide constants for the Attack Surface Engineering Platform.
No magic values should be scattered through scan logic — reference this file instead.
"""

# ─────────────────────────────────────────────
# Project identity
# ─────────────────────────────────────────────
PROJECT_NAME: str = "Attack Surface Engineering Platform"
PROJECT_VERSION: str = "0.1.0"
API_PREFIX: str = "/api/v1"

# ─────────────────────────────────────────────
# Scan status values
# Used across all scanners and the orchestrator.
# ─────────────────────────────────────────────
SCAN_STATUS_CREATED: str = "created"
SCAN_STATUS_QUEUED: str = "queued"
SCAN_STATUS_RUNNING: str = "running"
SCAN_STATUS_COMPLETED: str = "completed"
SCAN_STATUS_FAILED: str = "failed"
SCAN_STATUS_PARTIAL_FAILURE: str = "partial_failure"

# ─────────────────────────────────────────────
# Result confidence levels
# ─────────────────────────────────────────────
CONFIDENCE_HIGH: str = "high"
CONFIDENCE_MEDIUM: str = "medium"
CONFIDENCE_LOW: str = "low"

# ─────────────────────────────────────────────
# Result status values
# Used to express what was found (or not found).
# ─────────────────────────────────────────────
RESULT_STATUS_CONFIRMED: str = "confirmed"
RESULT_STATUS_DETECTED: str = "detected"
RESULT_STATUS_INFERRED: str = "inferred"
RESULT_STATUS_NOT_DETECTED: str = "not_detected"
RESULT_STATUS_UNKNOWN: str = "unknown"
RESULT_STATUS_FAILED: str = "failed"
RESULT_STATUS_NOT_TESTED: str = "not_tested"

# ─────────────────────────────────────────────
# Error type identifiers
# Every structured error must use one of these.
# ─────────────────────────────────────────────
ERROR_INVALID_INPUT: str = "invalid_input"
ERROR_INVALID_TARGET: str = "invalid_target"
ERROR_SCOPE_REJECTED: str = "scope_rejected"
ERROR_DNS_ERROR: str = "dns_error"
ERROR_CONNECTION_ERROR: str = "connection_error"
ERROR_CONNECTION_TIMEOUT: str = "connection_timeout"
ERROR_TLS_ERROR: str = "tls_error"
ERROR_HTTP_ERROR: str = "http_error"
ERROR_INVALID_RESPONSE: str = "invalid_response"
ERROR_PARSER_ERROR: str = "parser_error"
ERROR_DEPENDENCY_ERROR: str = "dependency_error"
ERROR_INTERNAL_ERROR: str = "internal_error"

# ─────────────────────────────────────────────
# Target type identifiers
# ─────────────────────────────────────────────
TARGET_TYPE_DOMAIN: str = "domain"
TARGET_TYPE_HOSTNAME: str = "hostname"
TARGET_TYPE_IPV4: str = "ipv4"
TARGET_TYPE_IPV6: str = "ipv6"
TARGET_TYPE_UNKNOWN: str = "unknown"

# ─────────────────────────────────────────────
# Scan tool identifiers
# Each scanner must register under one of these names.
# ─────────────────────────────────────────────
TOOL_DNS_SCAN: str = "dns_scan"
TOOL_PORT_DISCOVERY: str = "port_discovery"
TOOL_SERVICE_IDENTIFICATION: str = "service_identification"
TOOL_HTTP_SCAN: str = "http_scan"
TOOL_TECHNOLOGY_DETECTION: str = "technology_detection"
TOOL_ENDPOINT_DISCOVERY: str = "endpoint_discovery"
TOOL_JAVASCRIPT_DISCOVERY: str = "javascript_discovery"
TOOL_TLS_SCAN: str = "tls_scan"
TOOL_EMAIL_SECURITY: str = "email_security"
TOOL_CLOUD_CDN_DETECTION: str = "cloud_cdn_detection"

# ─────────────────────────────────────────────
# Asset type identifiers
# ─────────────────────────────────────────────
ASSET_TYPE_DOMAIN: str = "domain"
ASSET_TYPE_HOSTNAME: str = "hostname"
ASSET_TYPE_IP_ADDRESS: str = "ip_address"
ASSET_TYPE_DNS_RECORD: str = "dns_record"
ASSET_TYPE_NETWORK_PORT: str = "network_port"
ASSET_TYPE_NETWORK_SERVICE: str = "network_service"
ASSET_TYPE_URL: str = "url"
ASSET_TYPE_WEB_APPLICATION: str = "web_application"
ASSET_TYPE_WEB_ENDPOINT: str = "web_endpoint"
ASSET_TYPE_JAVASCRIPT_FILE: str = "javascript_file"
ASSET_TYPE_TLS_CERTIFICATE: str = "tls_certificate"
ASSET_TYPE_EMAIL_CONFIGURATION: str = "email_configuration"
ASSET_TYPE_TECHNOLOGY: str = "technology"
ASSET_TYPE_INFRASTRUCTURE_INDICATOR: str = "infrastructure_indicator"

# ─────────────────────────────────────────────
# Relationship type identifiers
# ─────────────────────────────────────────────
REL_RESOLVES_TO: str = "resolves_to"
REL_HAS_RECORD: str = "has_record"
REL_EXPOSES: str = "exposes"
REL_PROVIDES: str = "provides"
REL_SERVES: str = "serves"
REL_CONTAINS: str = "contains"
REL_LOADS: str = "loads"
REL_PRESENTS: str = "presents"
REL_PUBLISHES: str = "publishes"
