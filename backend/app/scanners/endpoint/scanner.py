"""
app/scanners/endpoint/scanner.py

Main Web Endpoint Discovery Scanner class subclassing BaseScanner.
Discovers and maps URLs, status codes, forms, resources, robots.txt, and sitemap.xml endpoints.
"""

import asyncio
import httpx

from app.core.constants import (
    CONFIDENCE_HIGH,
    TARGET_TYPE_DOMAIN,
    TARGET_TYPE_HOSTNAME,
    TARGET_TYPE_IPV4,
    TARGET_TYPE_IPV6,
    TOOL_ENDPOINT_DISCOVERY,
)
from app.models.evidence import Evidence
from app.scanners.base.base_scanner import BaseScanner
from app.scanners.base.exceptions import ScannerInputValidationError
from app.scanners.base.models import ScannerInput, ScannerResult
from app.scanners.endpoint.crawler import execute_crawl
from app.scanners.endpoint.models import EndpointRecord
from app.scanners.endpoint.normalizer import normalize_url
from app.scanners.endpoint.parsers.robots import parse_robots_txt
from app.scanners.endpoint.parsers.sitemap import parse_sitemap_xml
from app.scanners.endpoint.scope import is_url_in_scope


class EndpointScanner(BaseScanner):
    """
    Web Endpoint Discovery Scanner tool.
    Multi-source endpoint discovery parsing links, forms, scripts, resources, robots.txt, and sitemap.xml.
    """

    tool_name = TOOL_ENDPOINT_DISCOVERY

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
                f"Endpoint Scanner does not support target type '{target_type}'."
            )

    async def _execute(self, input_data: ScannerInput, result: ScannerResult) -> None:
        """
        Execute multi-source target endpoint discovery (Robots, Sitemap, HTML Crawler).
        """
        target = input_data.target.normalized
        config = input_data.configuration

        # Read configuration parameters
        timeout = float(config.get("timeout", 5.0))
        max_depth = int(config.get("max_depth", 2))
        max_pages = int(config.get("max_pages", 15))

        original_lower = input_data.target.original.strip().lower()
        if original_lower.startswith(("http://", "https://")):
            seeds = [input_data.target.original.strip()]
        else:
            seeds = [f"http://{target}/", f"https://{target}/"]

        records_map: dict[str, EndpointRecord] = {}

        limits = httpx.Limits(max_keepalive_connections=1, max_connections=2)
        async with httpx.AsyncClient(
            verify=False,
            limits=limits,
            timeout=timeout,
            follow_redirects=True,
        ) as client:

            # 1. Discover robots.txt
            sitemap_queue = []
            for seed in seeds:
                robots_url = f"{seed.rstrip('/')}/robots.txt"
                try:
                    resp = await client.get(robots_url)
                    if resp.status_code == 200:
                        norm_robots, _, _ = normalize_url(str(resp.url))
                        records_map[norm_robots] = EndpointRecord(
                            url=norm_robots,
                            status_code=200,
                            content_type=resp.headers.get("content-type"),
                            endpoint_type="PAGE",
                            discovery_source="robots_txt",
                            discovery_status="VERIFIED_LIVE",
                        )

                        paths, sitemaps = parse_robots_txt(str(resp.url), resp.text)
                        sitemap_queue.extend(sitemaps)

                        for p_url in paths:
                            norm_p, p_path, p_params = normalize_url(p_url)
                            if is_url_in_scope(norm_p, seed) and norm_p not in records_map:
                                records_map[norm_p] = EndpointRecord(
                                    url=norm_p,
                                    parent_url=norm_robots,
                                    endpoint_type="PAGE",
                                    discovery_source="robots_txt",
                                    discovery_status="DISCOVERED",
                                    query_parameters=p_params,
                                )
                except Exception:
                    pass

            # 2. Discover sitemap.xml
            for seed in seeds:
                sitemap_queue.append(f"{seed.rstrip('/')}/sitemap.xml")

            deduped_sitemaps = list(dict.fromkeys(sitemap_queue))
            for sm_url in deduped_sitemaps:
                try:
                    resp = await client.get(sm_url)
                    if resp.status_code == 200:
                        norm_sm, _, _ = normalize_url(str(resp.url))
                        records_map[norm_sm] = EndpointRecord(
                            url=norm_sm,
                            status_code=200,
                            content_type=resp.headers.get("content-type"),
                            endpoint_type="OTHER_RESOURCE",
                            discovery_source="sitemap_xml",
                            discovery_status="VERIFIED_LIVE",
                        )

                        loc_urls, child_sitemaps = parse_sitemap_xml(str(resp.url), resp.text)
                        for loc in loc_urls:
                            norm_loc, l_path, l_params = normalize_url(loc)
                            if is_url_in_scope(norm_loc, seeds[0]) and norm_loc not in records_map:
                                records_map[norm_loc] = EndpointRecord(
                                    url=norm_loc,
                                    parent_url=norm_sm,
                                    endpoint_type="PAGE",
                                    discovery_source="sitemap_xml",
                                    discovery_status="DISCOVERED",
                                    query_parameters=l_params,
                                )
                except Exception:
                    pass

        # 3. Execute Web Crawler
        async def _crawl_seed(seed_url: str) -> list[EndpointRecord]:
            try:
                return await execute_crawl(
                    seed_url,
                    max_depth=max_depth,
                    max_pages=max_pages,
                    timeout=timeout,
                )
            except Exception as e:
                self.logger.warning(
                    "Endpoint crawl failed for seed",
                    extra={
                        "seed": seed_url,
                        "error": str(e),
                    },
                )
                return []

        tasks = [_crawl_seed(seed) for seed in seeds]
        crawled_lists = await asyncio.gather(*tasks)

        # Merge crawler results (VERIFIED_LIVE takes precedence over static DISCOVERED)
        for crawled in crawled_lists:
            for rec in crawled:
                if rec.url not in records_map or rec.discovery_status == "VERIFIED_LIVE":
                    records_map[rec.url] = rec

        merged_results = list(records_map.values())
        result.results.extend(merged_results)

        # Append structured evidence
        for rec in merged_results:
            result.evidence.append(
                Evidence(
                    source_tool=self.tool_name,
                    discovery_method=rec.discovery_source,
                    raw_evidence={
                        "url": rec.url,
                        "status_code": rec.status_code,
                        "content_type": rec.content_type,
                        "parent_url": rec.parent_url,
                        "endpoint_type": rec.endpoint_type,
                        "discovery_source": rec.discovery_source,
                        "discovery_status": rec.discovery_status,
                        "http_method": rec.http_method,
                        "query_parameters": rec.query_parameters,
                        "form_inputs": rec.form_inputs,
                    },
                    confidence=CONFIDENCE_HIGH,
                )
            )

        # Sort results deterministically by URL
        result.results.sort(key=lambda x: x.url)
        result.evidence.sort(key=lambda x: x.raw_evidence["url"])
