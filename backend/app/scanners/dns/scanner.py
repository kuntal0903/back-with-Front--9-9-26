"""
app/scanners/dns/scanner.py

Main DNS Scanner class subclassing BaseScanner.
Queries A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, PTR records concurrently.
Supports custom resolvers and resolves discovered sub-hostnames within scope.
"""

import asyncio

from app.core.config import settings
from app.core.constants import (
    CONFIDENCE_HIGH,
    TARGET_TYPE_DOMAIN,
    TARGET_TYPE_HOSTNAME,
    TOOL_DNS_SCAN,
)
from app.models.evidence import Evidence
from app.scanners.base.base_scanner import BaseScanner
from app.scanners.base.exceptions import ScannerInputValidationError
from app.scanners.base.models import ScannerInput, ScannerResult
from app.scanners.dns.query import query_dns_record
from app.scanners.dns.validator import validate_dns_record, validate_fqdn


class DnsScanner(BaseScanner):
    """
    DNS Scanner tool.
    Resolves standard DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA, CAA, PTR)
    for target domains and hostnames, resolving discovered sub-hostnames.
    """

    tool_name = TOOL_DNS_SCAN

    def validate_input(self, input_data: ScannerInput) -> None:
        """
        Validate that the target is a domain or hostname.
        DNS lookups are not valid directly on raw IP targets.
        """
        target_type = input_data.target.target_type
        if target_type not in (TARGET_TYPE_DOMAIN, TARGET_TYPE_HOSTNAME):
            raise ScannerInputValidationError(
                f"DNS Scanner only supports domain or hostname targets. Target type is '{target_type}'."
            )

    async def _execute(self, input_data: ScannerInput, result: ScannerResult) -> None:
        """
        Execute concurrent DNS queries for all standard record types and resolve discovered sub-hostnames.
        """
        target = input_data.target.normalized
        config = input_data.configuration
        
        # Get query timeout from configuration, falling back to default
        timeout = float(config.get("timeout", settings.default_scan_timeout_seconds))
        resolvers = config.get("resolvers")

        # Standard record types to query
        record_types = ["A", "AAAA", "CNAME", "MX", "NS", "TXT", "SOA", "CAA", "PTR"]

        # Run primary queries concurrently
        tasks = [
            query_dns_record(target, rtype, timeout=timeout, nameservers=resolvers)
            for rtype in record_types
        ]

        query_results = await asyncio.gather(*tasks)

        # Track discovered hostnames to resolve A/AAAA records
        discovered_hostnames: set[str] = set()

        # Process and validate findings
        for rtype, records in zip(record_types, query_results):
            for record in records:
                # Syntactic validation of record values
                if not validate_dns_record(record):
                    self.logger.warning(
                        "DNS record failed format validation",
                        extra={
                            "target": target,
                            "record_type": rtype,
                            "value": record.value,
                        },
                    )
                    continue

                # Add to results list
                result.results.append(record)

                # Track discovered hostnames for secondary resolution
                if rtype in ("CNAME", "NS", "PTR"):
                    if validate_fqdn(record.value) and record.value != target:
                        discovered_hostnames.add(record.value)
                elif rtype == "MX":
                    parts = record.value.split()
                    mx_host = parts[1].rstrip(".") if len(parts) >= 2 else record.value.rstrip(".")
                    if validate_fqdn(mx_host) and mx_host != target:
                        discovered_hostnames.add(mx_host)

                # Store supporting evidence
                result.evidence.append(
                    Evidence(
                        source_tool=self.tool_name,
                        discovery_method="dns_query",
                        raw_evidence={
                            "record_type": record.record_type,
                            "value": record.value,
                            "ttl": record.ttl,
                            "preference": record.preference,
                            "extra": record.extra,
                        },
                        confidence=CONFIDENCE_HIGH,
                    )
                )

        # Secondary resolution for discovered hostnames (A / AAAA records)
        if discovered_hostnames:
            sub_tasks = []
            sub_hosts_list = list(discovered_hostnames)[:10]  # Bounded top 10 discovered hostnames
            for sub_host in sub_hosts_list:
                for sub_rtype in ("A", "AAAA"):
                    sub_tasks.append((sub_host, sub_rtype, query_dns_record(sub_host, sub_rtype, timeout=timeout, nameservers=resolvers)))

            sub_results = await asyncio.gather(*[t[2] for t in sub_tasks])

            for (sub_host, sub_rtype, _), records in zip(sub_tasks, sub_results):
                for record in records:
                    if validate_dns_record(record):
                        result.results.append(record)
                        result.evidence.append(
                            Evidence(
                                source_tool=self.tool_name,
                                discovery_method="dns_query_subdomain",
                                raw_evidence={
                                    "target_hostname": sub_host,
                                    "record_type": record.record_type,
                                    "value": record.value,
                                    "ttl": record.ttl,
                                    "extra": record.extra,
                                },
                                confidence=CONFIDENCE_HIGH,
                            )
                        )

        self.logger.debug(
            "DNS scan finished gathering",
            extra={
                "target": target,
                "results_count": len(result.results),
                "evidence_count": len(result.evidence),
            },
        )
