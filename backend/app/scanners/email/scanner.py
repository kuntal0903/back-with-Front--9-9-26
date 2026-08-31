"""
app/scanners/email/scanner.py

Main Email Security Scanner class subclassing BaseScanner.
Orchestrates DNS lookups (MX, SPF, DMARC, DKIM, TLS-RPT), MTA-STS policy fetching,
MX mail host resolution (A/AAAA/PTR), and safe SMTP protocol observation.
"""

import asyncio
from urllib.parse import urlparse

from app.core.constants import (
    CONFIDENCE_HIGH,
    TARGET_TYPE_DOMAIN,
    TARGET_TYPE_HOSTNAME,
    TOOL_EMAIL_SECURITY,
)
from app.models.evidence import Evidence
from app.scanners.base.base_scanner import BaseScanner
from app.scanners.base.exceptions import ScannerInputValidationError
from app.scanners.base.models import ScannerInput, ScannerResult
from app.scanners.email.dns_records import (
    query_dkim_record,
    query_mta_sts_policy,
    query_mx_exchanges,
    query_tls_rpt_record,
    query_txt_records,
    resolve_mail_host,
)
from app.scanners.email.models import DkimDetails, EmailRecord, MxHostDetail
from app.scanners.email.smtp_probe import probe_smtp_service
from app.scanners.email.validator import (
    parse_dkim_selector_record,
    validate_dmarc_records,
    validate_mta_sts_policy,
    validate_spf_records,
    validate_tls_rpt_record,
)

DEFAULT_DKIM_SELECTORS = ["default", "google", "k1", "mail", "key1", "smtp"]


class EmailScanner(BaseScanner):
    """
    Email Security Scanner tool.
    Analyzes MX, SPF, DMARC, DKIM, MTA-STS, TLS-RPT, and safe SMTP STARTTLS protocol behavior.
    """

    tool_name = TOOL_EMAIL_SECURITY

    def validate_input(self, input_data: ScannerInput) -> None:
        """
        Validate that the target is a valid domain or host.
        """
        target_type = input_data.target.target_type
        valid_types = (TARGET_TYPE_DOMAIN, TARGET_TYPE_HOSTNAME)
        original = input_data.target.original.lower().strip()
        is_url = original.startswith(("http://", "https://"))

        if target_type not in valid_types and not is_url:
            raise ScannerInputValidationError(
                f"Email Scanner does not support target type '{target_type}'."
            )

    async def _execute(self, input_data: ScannerInput, result: ScannerResult) -> None:
        """
        Run structured email infrastructure pipeline concurrently.
        """
        original = input_data.target.original.strip()

        if original.lower().startswith(("http://", "https://")):
            parsed = urlparse(original)
            domain = parsed.hostname or ""
        else:
            domain = input_data.target.normalized

        config = input_data.configuration
        timeout = float(config.get("timeout", 3.0))
        selectors = config.get("selectors", DEFAULT_DKIM_SELECTORS)
        if isinstance(selectors, str):
            selectors = [s.strip() for s in selectors.split(",") if s.strip()]

        # 1. Concurrent DNS & Policy fetches
        mx_task = query_mx_exchanges(domain, timeout)
        spf_task = query_txt_records(domain, timeout)
        dmarc_task = query_txt_records(f"_dmarc.{domain}", timeout)
        tls_rpt_task = query_txt_records(f"_smtp._tls.{domain}", timeout)
        mta_sts_task = query_mta_sts_policy(domain, timeout)

        mx_res, apex_txt_records, dmarc_txt_records, tls_rpt_txt_records, mta_sts_res = await asyncio.gather(
            mx_task, spf_task, dmarc_task, tls_rpt_task, mta_sts_task
        )

        if isinstance(mx_res, tuple) and len(mx_res) == 2 and isinstance(mx_res[0], str):
            dns_status, raw_mx = mx_res
        else:
            dns_status, raw_mx = ("VALID_MX", mx_res)

        mx_exchanges = []
        if isinstance(raw_mx, list):
            for item in raw_mx:
                if isinstance(item, tuple) and len(item) == 2:
                    mx_exchanges.append(item)
                elif isinstance(item, str):
                    mx_exchanges.append((10, item))

        mta_sts_status, mta_sts_content = mta_sts_res if isinstance(mta_sts_res, tuple) else (None, None)

        # DKIM selectors queries
        dkim_tasks = [query_dkim_record(sel, domain, timeout) for sel in selectors]
        dkim_responses = await asyncio.gather(*dkim_tasks)

        dkim_found = {}
        parsed_dkims = []
        for sel, raw_rec in zip(selectors, dkim_responses):
            if raw_rec:
                dkim_found[sel] = raw_rec
                parsed_dkims.append(parse_dkim_selector_record(sel, raw_rec))

        # 2. MX Host Resolution (A/AAAA/PTR)
        mx_details: list[MxHostDetail] = []
        mx_hostnames = [ex[1] for ex in mx_exchanges]

        async def _resolve_mx(prio: int, mx_host: str) -> tuple[MxHostDetail, list[str]]:
            v4s, v6s, ptrs = await resolve_mail_host(mx_host, timeout)
            res_status = "resolved" if (v4s or v6s) else "no_ip"
            detail = MxHostDetail(
                hostname=mx_host,
                priority=prio,
                ipv4_addresses=v4s,
                ipv6_addresses=v6s,
                ptr_records=ptrs,
                resolution_status=res_status,
            )
            return detail, (v4s + v6s)

        mx_res_tasks = [_resolve_mx(prio, host) for prio, host in mx_exchanges]
        mx_resolutions = await asyncio.gather(*mx_res_tasks) if mx_res_tasks else []

        all_target_ips = []
        for mx_detail, ips in mx_resolutions:
            mx_details.append(mx_detail)
            all_target_ips.extend([(mx_detail.hostname, ip) for ip in ips])

        # 3. Safe SMTP Protocol Observations (probing first 2 MX IPs safely)
        smtp_details_list = []
        if all_target_ips:
            bounded_smtp_targets = all_target_ips[:2]
            smtp_tasks = [probe_smtp_service(host, ip, port=25, timeout=timeout) for host, ip in bounded_smtp_targets]
            smtp_details_list = await asyncio.gather(*smtp_tasks)

        # 4. Validate SPF, DMARC, MTA-STS, TLS-RPT
        spf_details = validate_spf_records(apex_txt_records)
        dmarc_details = validate_dmarc_records(dmarc_txt_records)
        dkim_details = DkimDetails(
            selectors_checked=selectors,
            selectors_found=dkim_found,
            parsed_selectors=parsed_dkims,
        )
        mta_sts_details = validate_mta_sts_policy(mta_sts_status, mta_sts_content)
        tls_rpt_details = validate_tls_rpt_record(tls_rpt_txt_records)

        # 5. Populate Results
        record = EmailRecord(
            domain=domain,
            dns_status=dns_status,
            mx_records=mx_hostnames,
            mx_details=mx_details,
            spf=spf_details,
            dmarc=dmarc_details,
            dkim=dkim_details,
            mta_sts=mta_sts_details,
            tls_rpt=tls_rpt_details,
            smtp_details=smtp_details_list,
        )
        result.results.append(record)

        # 6. Store supporting evidence
        result.evidence.append(
            Evidence(
                source_tool=self.tool_name,
                discovery_method="dns_lookup",
                raw_evidence={
                    "domain": domain,
                    "dns_status": dns_status,
                    "mx_records_count": len(mx_hostnames),
                    "mx_exchanges": mx_hostnames,
                    "mx_details": [m.model_dump() for m in mx_details],
                    "spf_found": spf_details.record_found,
                    "spf_valid": spf_details.is_valid,
                    "spf_strength": spf_details.strength,
                    "spf_mechanisms": spf_details.mechanisms,
                    "spf_includes": spf_details.includes,
                    "dmarc_found": dmarc_details.record_found,
                    "dmarc_valid": dmarc_details.is_valid,
                    "dmarc_policy": dmarc_details.policy,
                    "dkim_selectors_checked": selectors,
                    "dkim_selectors_found_count": len(dkim_found),
                    "mta_sts_found": mta_sts_details.found,
                    "mta_sts_mode": mta_sts_details.mode,
                    "tls_rpt_found": tls_rpt_details.found,
                    "smtp_observations_count": len(smtp_details_list),
                },
                confidence=CONFIDENCE_HIGH,
            )
        )
