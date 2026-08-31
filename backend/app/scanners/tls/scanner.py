"""
app/scanners/tls/scanner.py

Main TLS/Certificate Scanner class subclassing BaseScanner.
Handles TLS handshakes, SNI, ALPN negotiation, certificate decoding, and validator policies.
"""

import asyncio
import ipaddress
from urllib.parse import urlparse

from app.core.constants import (
    CONFIDENCE_HIGH,
    TARGET_TYPE_DOMAIN,
    TARGET_TYPE_HOSTNAME,
    TARGET_TYPE_IPV4,
    TARGET_TYPE_IPV6,
    TOOL_TLS_SCAN,
)
from app.models.evidence import Evidence
from app.scanners.base.base_scanner import BaseScanner
from app.scanners.base.exceptions import (
    ScannerConnectionError,
    ScannerInputValidationError,
    ScannerTimeoutError,
)
from app.scanners.base.models import ScannerInput, ScannerResult
from app.scanners.tls.handshake import execute_tls_handshake
from app.scanners.tls.models import TlsRecord
from app.scanners.tls.parser import parse_der_certificate
from app.scanners.tls.validator import (
    evaluate_hostname_verification,
    evaluate_trust_status,
    probe_supported_protocols,
    probe_weak_ciphers,
)


class TlsScanner(BaseScanner):
    """
    TLS/Certificate Scanner tool.
    Collects SSL/TLS version capabilities, ALPN negotiation, weak ciphers, and decodes peer certificates.
    """

    tool_name = TOOL_TLS_SCAN

    def validate_input(self, input_data: ScannerInput) -> None:
        """
        Validate that the target is a valid host or URL.
        """
        target_type = input_data.target.target_type
        valid_types = (
            TARGET_TYPE_IPV4,
            TARGET_TYPE_IPV6,
            TARGET_TYPE_DOMAIN,
            TARGET_TYPE_HOSTNAME,
        )
        original = input_data.target.original.lower().strip()
        is_url = original.startswith(("http://", "https://"))

        if target_type not in valid_types and not is_url:
            raise ScannerInputValidationError(
                f"TLS Scanner does not support target type '{target_type}'."
            )

    async def _execute(self, input_data: ScannerInput, result: ScannerResult) -> None:
        """
        Connect to the target over SSL/TLS, download and parse certificates,
        and validate security policies.
        """
        original = input_data.target.original.strip()

        # Resolve target host
        if original.lower().startswith(("http://", "https://")):
            parsed = urlparse(original)
            host = parsed.hostname or ""
        else:
            host = input_data.target.normalized

        config = input_data.configuration
        port = int(config.get("port", 443))
        timeout = float(config.get("timeout", 3.0))

        # Check IP version
        ip_ver = None
        is_ip = False
        try:
            ip_obj = ipaddress.ip_address(host)
            ip_ver = f"IPv{ip_obj.version}"
            is_ip = True
        except ValueError:
            pass

        sni_name = None if is_ip else host

        # 1. Execute initial TLS handshake
        try:
            handshake_res = execute_tls_handshake(host, port, timeout=timeout)
            if len(handshake_res) >= 4:
                der_bytes, negotiated_version, negotiated_cipher, alpn_negotiated = handshake_res[:4]
            else:
                der_bytes, negotiated_version, negotiated_cipher = handshake_res[:3]
                alpn_negotiated = None
            conn_status = "success"
        except ScannerTimeoutError as e:
            self.logger.warning(f"TLS connection timeout for {host}:{port}")
            result.errors.append(str(e))
            return
        except ScannerConnectionError as e:
            self.logger.warning(f"TLS connection error for {host}:{port}")
            result.errors.append(str(e))
            return

        # 2. Parse Certificate Metadata
        cert_details = parse_der_certificate(der_bytes)

        # 3. Assess Trust Status & Hostname Verification
        trust_status = evaluate_trust_status(host, cert_details)
        hostname_ver = evaluate_hostname_verification(host, cert_details)

        # 4. Probe TLS versions and weak ciphers support (run in executor)
        loop = asyncio.get_running_loop()
        supported_protocols = await loop.run_in_executor(
            None, probe_supported_protocols, host, port, timeout
        )
        weak_accepted, weak_negotiated = await loop.run_in_executor(
            None, probe_weak_ciphers, host, port, timeout
        )

        # 5. Populate Results
        record = TlsRecord(
            port=port,
            host=host,
            ip_address=host if is_ip else None,
            ip_version=ip_ver,
            sni_hostname=sni_name,
            negotiated_tls_version=negotiated_version,
            negotiated_cipher=negotiated_cipher,
            alpn_negotiated=alpn_negotiated or "none",
            certificate=cert_details,
            chain_status="complete",
            supported_protocols=supported_protocols,
            weak_ciphers_accepted=weak_accepted,
            weak_ciphers_negotiated=weak_negotiated,
            trust_status=trust_status,
            hostname_verification=hostname_ver,
            connection_status=conn_status,
        )
        result.results.append(record)

        # 6. Store evidence
        result.evidence.append(
            Evidence(
                source_tool=self.tool_name,
                discovery_method="tls_handshake",
                raw_evidence={
                    "host": host,
                    "port": port,
                    "sni_hostname": sni_name,
                    "negotiated_version": negotiated_version,
                    "negotiated_cipher": negotiated_cipher,
                    "alpn_negotiated": alpn_negotiated or "none",
                    "trust_status": trust_status,
                    "hostname_verification": hostname_ver,
                    "subject": cert_details.subject,
                    "issuer": cert_details.issuer,
                    "fingerprint_sha256": cert_details.fingerprint_sha256,
                    "validity_start": cert_details.validity_start,
                    "validity_end": cert_details.validity_end,
                    "subject_alt_names": cert_details.subject_alt_names,
                    "supported_protocols": supported_protocols,
                    "weak_ciphers_accepted": weak_accepted,
                },
                confidence=CONFIDENCE_HIGH,
            )
        )
