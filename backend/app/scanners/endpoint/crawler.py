"""
app/scanners/endpoint/crawler.py

Asynchronous queue-based web crawling loop with same-origin, depth, and resource constraints.
Parses HTML links, forms, scripts, stylesheets, and resources.
"""

import asyncio
import time
import httpx

from app.scanners.endpoint.extractor import extract_html_resources
from app.scanners.endpoint.models import EndpointRecord
from app.scanners.endpoint.normalizer import normalize_url
from app.scanners.endpoint.parsers.forms import parse_html_forms
from app.scanners.endpoint.scope import is_url_in_scope

_MAX_RESPONSE_BODY_BYTES = 5 * 1024 * 1024  # 5MB response payload limit


async def execute_crawl(
    seed_url: str,
    max_depth: int = 2,
    max_pages: int = 15,
    timeout: float = 5.0,
) -> list[EndpointRecord]:
    """
    Crawl HTML endpoints recursively from a starting seed URL.
    
    Args:
        seed_url: Seed/Origin URL.
        max_depth: Maximum recursion level (0-indexed).
        max_pages: Maximum responsive pages to crawl before stopping.
        timeout: Network request timeout in seconds.
        
    Returns:
        list[EndpointRecord]: Discovered endpoint records.
    """
    visited_urls = set()
    records_dict: dict[str, EndpointRecord] = {}

    # BFS queue holding tuples of: (url, current_depth, parent_url)
    queue = [(seed_url, 0, None)]

    limits = httpx.Limits(max_keepalive_connections=1, max_connections=2)

    async with httpx.AsyncClient(
        verify=False,
        limits=limits,
        timeout=timeout,
        follow_redirects=True,
    ) as client:
        while queue and len(visited_urls) < max_pages:
            url, depth, parent = queue.pop(0)

            norm_url, path, query_params = normalize_url(url)
            if norm_url in visited_urls:
                continue

            visited_urls.add(norm_url)

            start_time = time.perf_counter()
            try:
                response = await client.get(norm_url)
                duration = time.perf_counter() - start_time
                content_type = response.headers.get("content-type", "")

                # 5MB body size protection
                body_bytes = response.content[:_MAX_RESPONSE_BODY_BYTES]
                html_body = body_bytes.decode("utf-8", errors="replace")
                final_url = str(response.url)
                status_code = response.status_code

            except Exception:
                # If network connection failed or timed out, skip fetching deeper
                continue

            # Record verified live page endpoint
            final_norm_url, final_path, final_params = normalize_url(final_url)

            # Classify endpoint type
            endpoint_type = "PAGE"
            if any(marker in final_path.lower() for marker in ("/api/", "/v1/", "/v2/", "/graphql", "/swagger", "/openapi")):
                endpoint_type = "API"

            live_rec = EndpointRecord(
                url=final_norm_url,
                status_code=status_code,
                content_type=content_type,
                response_time_seconds=duration,
                parent_url=parent,
                endpoint_type=endpoint_type,
                discovery_source="html_anchor" if parent else "seed",
                discovery_status="VERIFIED_LIVE",
                http_method="GET",
                query_parameters=final_params,
            )
            records_dict[final_norm_url] = live_rec

            # Check max_pages boundary
            if len(visited_urls) >= max_pages:
                break

            # Recursively extract HTML resources & forms ONLY if depth < max_depth
            is_html = "text/html" in content_type.lower()

            if depth < max_depth and is_html:
                # 1. Parse Forms
                forms = parse_html_forms(final_norm_url, html_body)
                for f in forms:
                    f_norm_url, f_path, f_params = normalize_url(f.action_url)
                    if is_url_in_scope(f_norm_url, seed_url):
                        form_rec = EndpointRecord(
                            url=f_norm_url,
                            status_code=None,
                            content_type=None,
                            response_time_seconds=None,
                            parent_url=final_norm_url,
                            endpoint_type="FORM",
                            discovery_source="html_form",
                            discovery_status="DISCOVERED",
                            http_method=f.method,
                            query_parameters=f.param_names,
                            form_inputs=f.inputs,
                        )
                        if f_norm_url not in records_dict:
                            records_dict[f_norm_url] = form_rec

                # 2. Parse HTML Resources & Links
                extracted_resources = extract_html_resources(final_norm_url, html_body)
                for res in extracted_resources:
                    if is_url_in_scope(res.normalized_url, seed_url):
                        if res.normalized_url not in records_dict:
                            res_rec = EndpointRecord(
                                url=res.normalized_url,
                                status_code=None,
                                content_type=None,
                                response_time_seconds=None,
                                parent_url=final_norm_url,
                                endpoint_type=res.resource_type,
                                discovery_source=res.discovery_source,
                                discovery_status="DISCOVERED",
                                http_method="GET",
                                query_parameters=res.query_params,
                            )
                            records_dict[res.normalized_url] = res_rec

                        # Queue in-scope links for deeper crawl iteration
                        if res.resource_type in ("PAGE", "API") and res.normalized_url not in visited_urls:
                            queue.append((res.normalized_url, depth + 1, final_norm_url))

    # Return only records corresponding to fetched pages or extracted resources within max_pages limit
    fetched_records = [r for r in records_dict.values() if r.url in visited_urls or r.discovery_status == "VERIFIED_LIVE"]
    if len(fetched_records) >= max_pages:
        return fetched_records[:max_pages]

    return list(records_dict.values())
