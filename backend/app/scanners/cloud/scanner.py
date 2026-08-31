"""
app/scanners/cloud/scanner.py

Main Cloud/CDN Detection Scanner class subclassing BaseScanner.
Orchestrates CNAME chain traversal, IP range ownership checks, HTTP headers inspection,
TLS certificate correlation, multi-signal evidence aggregation, and confidence scoring.
"""

import asyncio
import dns.asyncresolver
import httpx
from urllib.parse import urlparse

from app.core.constants import (
    CONFIDENCE_HIGH,
    TARGET_TYPE_DOMAIN,
    TARGET_TYPE_HOSTNAME,
    TARGET_TYPE_IPV4,
    TARGET_TYPE_IPV6,
    TOOL_CLOUD_CDN_DETECTION,
)
from app.models.evidence import Evidence
from app.scanners.base.base_scanner import BaseScanner
from app.scanners.base.exceptions import ScannerInputValidationError
from app.scanners.base.models import ScannerInput, ScannerResult
from app.scanners.cloud.analyzer import (
    analyze_cname_details,
    analyze_headers_details,
    analyze_tls_certificate,
)
from app.scanners.cloud.models import (
    CdnFinding,
    CloudCdnRecord,
    CloudFinding,
    NetworkOwnership,
    WafFinding,
)
from app.scanners.cloud.ranges import find_ip_provider_details
from app.scanners.tls.handshake import execute_tls_handshake
from app.scanners.tls.parser import parse_der_certificate

_MAX_CNAME_DEPTH = 5


class CloudScanner(BaseScanner):
    """
    Advanced Cloud/CDN Detection Scanner tool.
    Correlates CNAME chains, IP/ASN ownership, HTTP headers, and TLS certificates into evidence-backed findings.
    """

    tool_name = TOOL_CLOUD_CDN_DETECTION

    def validate_input(self, input_data: ScannerInput) -> None:
        """
        Validate that the target is a valid host, IP, or URL.
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
                f"Cloud Scanner does not support target type '{target_type}'."
            )

    async def _execute(self, input_data: ScannerInput, result: ScannerResult) -> None:
        """
        Identify hosting, CDN, and WAF providers through multi-signal correlation.
        """
        original = input_data.target.original.strip()
        target_type = input_data.target.target_type

        if original.lower().startswith(("http://", "https://")):
            parsed = urlparse(original)
            host = parsed.hostname or ""
            seeds = [original]
        else:
            host = input_data.target.normalized
            seeds = [f"http://{host}/", f"https://{host}/"]

        config = input_data.configuration
        timeout = float(config.get("timeout", 3.0))

        is_ip = target_type in (TARGET_TYPE_IPV4, TARGET_TYPE_IPV6)

        cname_chain: list[str] = []
        resolved_ips: list[str] = []
        network_info: NetworkOwnership | None = None
        cdn_finding: CdnFinding | None = None
        waf_finding: WafFinding | None = None
        cloud_finding: CloudFinding | None = None

        evidence_signals: list[str] = []
        primary_method: str | None = None

        # CASE A: Target is a raw IP address
        if is_ip:
            resolved_ips.append(host)
            ip_match = find_ip_provider_details(host)
            if ip_match:
                provider, matched_cidr, is_cdn, is_waf, org = ip_match
                network_info = NetworkOwnership(ip=host, cidr=matched_cidr, organization=org)
                evidence_signals.append(f"IP {host} matched CIDR {matched_cidr} ({org})")
                primary_method = "ip_range"

                if is_cdn:
                    cdn_finding = CdnFinding(provider=provider, confidence="LIKELY", evidence=[f"IP CIDR {matched_cidr}"])
                else:
                    cloud_finding = CloudFinding(provider=provider, relationship="NETWORK_OWNER", confidence="LIKELY", evidence=[f"IP CIDR {matched_cidr}"])
                if is_waf:
                    waf_finding = WafFinding(provider=provider, confidence="LIKELY", evidence=[f"IP CIDR {matched_cidr}"])
        else:
            # CASE B: Target is a domain/hostname. Execute DNS, HTTP, and TLS probes concurrently.
            resolver = dns.asyncresolver.Resolver()
            resolver.timeout = timeout
            resolver.lifetime = timeout

            async def _dns_probe() -> tuple[list[str], list[str]]:
                chain = []
                curr = host
                depth = 0
                while depth < _MAX_CNAME_DEPTH:
                    try:
                        ans = await resolver.resolve(curr, "CNAME")
                        next_target = str(ans[0].target).strip().rstrip(".")
                        if next_target and next_target != curr:
                            chain.append(next_target)
                            curr = next_target
                            depth += 1
                        else:
                            break
                    except Exception:
                        break

                ips = []
                for rtype in ("A", "AAAA"):
                    try:
                        ans_ip = await resolver.resolve(host, rtype)
                        for rdata in ans_ip:
                            ips.append(str(rdata).strip())
                    except Exception:
                        pass
                return chain, ips

            async def _http_headers_probe() -> dict[str, str]:
                async def _try_seed(url: str) -> dict[str, str]:
                    try:
                        async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=True) as client:
                            resp = await client.head(url)
                            return {k.lower(): v for k, v in resp.headers.items()}
                    except Exception:
                        try:
                            async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=True) as client:
                                resp = await client.get(url)
                                return {k.lower(): v for k, v in resp.headers.items()}
                        except Exception:
                            return {}

                results = await asyncio.gather(*[_try_seed(s) for s in seeds])
                for res in results:
                    if res:
                        return res
                return {}

            async def _tls_probe() -> tuple[dict[str, str], list[str]]:
                try:
                    der_bytes, _, _ = execute_tls_handshake(host, 443, timeout=timeout)
                    cert_details = parse_der_certificate(der_bytes)
                    return cert_details.issuer, cert_details.subject_alt_names
                except Exception:
                    return {}, []

            (cname_chain, resolved_ips), http_headers, (cert_issuer, cert_sans) = await asyncio.gather(
                _dns_probe(), _http_headers_probe(), _tls_probe()
            )

            cdn_signals: dict[str, list[str]] = {}
            waf_signals: dict[str, list[str]] = {}
            cloud_signals: dict[str, list[str]] = {}

            # 1. CNAME chain analysis
            for cname in cname_chain:
                cname_match = analyze_cname_details(cname)
                if cname_match:
                    prov, is_c, is_w = cname_match
                    sig_str = f"CNAME target: {cname}"
                    evidence_signals.append(sig_str)
                    if not primary_method:
                        primary_method = "dns_cname"
                    if is_c:
                        cdn_signals.setdefault(prov, []).append(sig_str)
                    else:
                        cloud_signals.setdefault(prov, []).append(sig_str)
                    if is_w:
                        waf_signals.setdefault(prov, []).append(sig_str)

            # 2. HTTP headers analysis
            if http_headers:
                header_matches = analyze_headers_details(http_headers)
                for prov, is_c, is_w, sig_str in header_matches:
                    evidence_signals.append(sig_str)
                    if not primary_method:
                        primary_method = "http_headers"
                    if is_c:
                        cdn_signals.setdefault(prov, []).append(sig_str)
                    else:
                        cloud_signals.setdefault(prov, []).append(sig_str)
                    if is_w:
                        waf_signals.setdefault(prov, []).append(sig_str)

            # 3. TLS cert analysis
            if cert_issuer or cert_sans:
                cert_matches = analyze_tls_certificate(cert_issuer, cert_sans)
                for prov, is_c, is_w, sig_str in cert_matches:
                    evidence_signals.append(sig_str)
                    if is_c:
                        cdn_signals.setdefault(prov, []).append(sig_str)
                    else:
                        cloud_signals.setdefault(prov, []).append(sig_str)
                    if is_w:
                        waf_signals.setdefault(prov, []).append(sig_str)

            # 4. IP Range analysis
            if resolved_ips:
                for ip in resolved_ips:
                    ip_match = find_ip_provider_details(ip)
                    if ip_match:
                        prov, cidr, is_c, is_w, org = ip_match
                        sig_str = f"Resolved IP {ip} matched CIDR {cidr} ({org})"
                        evidence_signals.append(sig_str)
                        if not primary_method:
                            primary_method = "ip_range"

                        if not network_info:
                            network_info = NetworkOwnership(ip=ip, cidr=cidr, organization=org)

                        if is_c:
                            cdn_signals.setdefault(prov, []).append(sig_str)
                        else:
                            cloud_signals.setdefault(prov, []).append(sig_str)
                        if is_w:
                            waf_signals.setdefault(prov, []).append(sig_str)

            if cdn_signals:
                best_cdn_prov = max(cdn_signals.keys(), key=lambda k: len(cdn_signals[k]))
                sigs = cdn_signals[best_cdn_prov]
                conf = "CONFIRMED" if len(sigs) >= 2 else "LIKELY"
                cdn_finding = CdnFinding(provider=best_cdn_prov, confidence=conf, evidence=sigs)

            if waf_signals:
                best_waf_prov = max(waf_signals.keys(), key=lambda k: len(waf_signals[k]))
                sigs = waf_signals[best_waf_prov]
                conf = "CONFIRMED" if len(sigs) >= 2 else "LIKELY"
                waf_finding = WafFinding(provider=best_waf_prov, confidence=conf, evidence=sigs)

            if cloud_signals:
                best_cloud_prov = max(cloud_signals.keys(), key=lambda k: len(cloud_signals[k]))
                sigs = cloud_signals[best_cloud_prov]
                conf = "CONFIRMED" if len(sigs) >= 2 else "LIKELY"
                cloud_finding = CloudFinding(provider=best_cloud_prov, relationship="NETWORK_OWNER", confidence=conf, evidence=sigs)

        primary_provider = None
        primary_evidence = None

        if cdn_finding:
            primary_provider = cdn_finding.provider
            primary_evidence = cdn_finding.evidence[0] if cdn_finding.evidence else None
        elif cloud_finding:
            primary_provider = cloud_finding.provider
            primary_evidence = cloud_finding.evidence[0] if cloud_finding.evidence else None

        edge_ip = resolved_ips[0] if resolved_ips else None
        record = CloudCdnRecord(
            target=original,
            is_cloud=cloud_finding is not None or (cdn_finding is not None and not cdn_finding.provider.startswith("Cloudflare")),
            is_cdn=cdn_finding is not None,
            is_waf=waf_finding is not None,
            provider=primary_provider,
            detection_method=primary_method,
            matched_evidence=primary_evidence,
            network=network_info,
            cname_chain=cname_chain,
            cdn=cdn_finding,
            waf=waf_finding,
            cloud=cloud_finding,
            observed_edge_ip=edge_ip,
            origin_ip="unknown",
        )
        result.results.append(record)

        result.evidence.append(
            Evidence(
                source_tool=self.tool_name,
                discovery_method=primary_method or "multi_signal_correlation",
                raw_evidence={
                    "target": original,
                    "host": host,
                    "cname_chain": cname_chain,
                    "resolved_ips": resolved_ips,
                    "network": network_info.model_dump() if network_info else None,
                    "cdn": cdn_finding.model_dump() if cdn_finding else None,
                    "waf": waf_finding.model_dump() if waf_finding else None,
                    "cloud": cloud_finding.model_dump() if cloud_finding else None,
                    "evidence_signals": evidence_signals,
                },
                confidence=CONFIDENCE_HIGH,
            )
        )
