"""
app/scanners/js/scanner.py

Main JavaScript Discovery Scanner class subclassing BaseScanner.
Probes target page, locates inline/external script tags, enforces Content-Type and payload bounds,
and performs static analysis to extract REST paths, WebSockets, hostnames, request calls, and credentials.
"""

import asyncio
import ssl
import httpx

from app.core.config import settings
from app.core.constants import (
    CONFIDENCE_HIGH,
    TARGET_TYPE_DOMAIN,
    TARGET_TYPE_HOSTNAME,
    TARGET_TYPE_IPV4,
    TARGET_TYPE_IPV6,
    TOOL_JAVASCRIPT_DISCOVERY,
)
from app.models.evidence import Evidence
from app.scanners.base.base_scanner import BaseScanner
from app.scanners.base.exceptions import ScannerInputValidationError
from app.scanners.base.models import ScannerInput, ScannerResult
from app.scanners.js.extractor import extract_js_references
from app.scanners.js.models import JsRecord, JsScriptDetails
from app.scanners.js.parser import extract_script_sources

_MAX_SCRIPT_BYTES = 5 * 1024 * 1024  # 5MB per script file
_MAX_SCRIPTS_PER_SEED = 20  # Limit script downloads per seed page


class JsScanner(BaseScanner):
    """
    JavaScript Discovery Scanner tool.
    Finds inline/external script references and statically analyzes them for endpoints, WebSockets, and credentials.
    """

    tool_name = TOOL_JAVASCRIPT_DISCOVERY

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
                f"JavaScript Scanner does not support target type '{target_type}'."
            )

    async def _execute(self, input_data: ScannerInput, result: ScannerResult) -> None:
        """
        Execute scripts discovery. Probes HTTP/HTTPS seeds if bare target is provided.
        """
        target = input_data.target.normalized
        config = input_data.configuration

        # Read configuration parameters
        timeout = float(config.get("timeout", 3.0))

        original_lower = input_data.target.original.strip().lower()
        if original_lower.startswith(("http://", "https://")):
            seeds = [input_data.target.original.strip()]
        else:
            seeds = [f"http://{target}/", f"https://{target}/"]

        async def _probe_seed(seed_url: str) -> None:
            try:
                # Query index page content
                headers, html_body = await self._grab_url_content(seed_url, timeout)

                # Extract script details
                inline_blocks, external_urls = extract_script_sources(seed_url, html_body)

                script_records: list[JsScriptDetails] = []

                # 1. Parse inline blocks (merge all inline results into a single record)
                all_inline_refs = []
                for inline_code in inline_blocks:
                    refs, _, _ = extract_js_references(inline_code, source_file="inline", origin_page_url=seed_url)
                    all_inline_refs.extend(refs)

                if all_inline_refs:
                    # Deduplicate references
                    seen_inline = set()
                    deduped_inline_refs = []
                    for r in all_inline_refs:
                        k = (r.value, r.type, r.http_method)
                        if k not in seen_inline:
                            seen_inline.add(k)
                            deduped_inline_refs.append(r)

                    sm_url = next((r.value for r in deduped_inline_refs if r.type == "source_map"), None)
                    inline_paths = [r.value for r in deduped_inline_refs if r.type in ("relative_path", "api_endpoint", "absolute_url")]
                    inline_secrets = [r.value for r in deduped_inline_refs if r.type == "secret"]

                    inline_details = JsScriptDetails(
                        script_url="inline",
                        content_type="text/html",
                        file_size_bytes=sum(len(b) for b in inline_blocks),
                        is_minified=False,
                        source_map_url=sm_url,
                        references=deduped_inline_refs,
                        discovered_paths=sorted(list(set(inline_paths))),
                        discovered_secrets=sorted(list(set(inline_secrets))),
                    )
                    script_records.append(inline_details)

                # 2. Query and parse external script assets concurrently (capped by _MAX_SCRIPTS_PER_SEED)
                bounded_external_urls = external_urls[:_MAX_SCRIPTS_PER_SEED]

                async def _parse_external_js(js_url: str) -> JsScriptDetails | None:
                    try:
                        resp_headers, js_content = await self._grab_url_content(js_url, timeout)
                        content_type = resp_headers.get("content-type", "")

                        refs, paths, secrets = extract_js_references(
                            js_content, source_file=js_url, origin_page_url=seed_url
                        )
                        sm_url = next((r.value for r in refs if r.type == "source_map"), None)
                        is_min = len(js_content) > 500 and ("\n" not in js_content or len(js_content.splitlines()) < 5)

                        if refs or paths or secrets:
                            return JsScriptDetails(
                                script_url=js_url,
                                content_type=content_type,
                                file_size_bytes=len(js_content),
                                is_minified=is_min,
                                source_map_url=sm_url,
                                references=refs,
                                discovered_paths=sorted(paths),
                                discovered_secrets=sorted(secrets),
                            )
                    except Exception:
                        # Fail gracefully for individual missing script files
                        pass
                    return None

                if bounded_external_urls:
                    ext_tasks = [_parse_external_js(url) for url in bounded_external_urls]
                    ext_results = await asyncio.gather(*ext_tasks)
                    for r in ext_results:
                        if r is not None:
                            script_records.append(r)

                # Append to scanner findings if any endpoints/secrets discovered
                if script_records:
                    record = JsRecord(
                        origin_url=seed_url,
                        scripts=script_records,
                    )
                    result.results.append(record)

                    # Store supporting evidence
                    for s_rec in script_records:
                        result.evidence.append(
                            Evidence(
                                source_tool=self.tool_name,
                                discovery_method="javascript_parser",
                                raw_evidence={
                                    "origin_url": seed_url,
                                    "script_url": s_rec.script_url,
                                    "content_type": s_rec.content_type,
                                    "file_size_bytes": s_rec.file_size_bytes,
                                    "is_minified": s_rec.is_minified,
                                    "source_map_url": s_rec.source_map_url,
                                    "paths_count": len(s_rec.discovered_paths),
                                    "secrets_count": len(s_rec.discovered_secrets),
                                    "references_count": len(s_rec.references),
                                    "paths": s_rec.discovered_paths,
                                    "secrets": s_rec.discovered_secrets,
                                    "references": [ref.model_dump() for ref in s_rec.references],
                                },
                                confidence=CONFIDENCE_HIGH,
                            )
                        )
            except Exception as e:
                self.logger.warning(
                    "JavaScript scan failed for seed",
                    extra={
                        "seed": seed_url,
                        "error": str(e),
                    },
                )

        # Launch probes concurrently
        tasks = [_probe_seed(seed) for seed in seeds]
        await asyncio.gather(*tasks)

        # Sort results deterministically
        result.results.sort(key=lambda x: x.origin_url)
        result.evidence.sort(key=lambda x: x.raw_evidence["script_url"])

    async def _grab_url_content(self, url: str, timeout: float) -> tuple[dict[str, str], str]:
        """
        Request URL content with SSL validation fallback and 5MB size limit.
        """
        try:
            return await self._execute_request(url, timeout, verify_ssl=True)
        except httpx.RequestError as e:
            err_str = str(e).lower()
            underlying = e.__cause__
            is_ssl_err = "ssl" in err_str or "cert" in err_str
            if underlying:
                underlying_str = str(underlying).lower()
                if "ssl" in underlying_str or "cert" in underlying_str or isinstance(underlying, ssl.SSLError):
                    is_ssl_err = True

            if is_ssl_err:
                return await self._execute_request(url, timeout, verify_ssl=False)
            raise e

    async def _execute_request(self, url: str, timeout: float, verify_ssl: bool) -> tuple[dict[str, str], str]:
        limits = httpx.Limits(max_keepalive_connections=1, max_connections=2)
        async with httpx.AsyncClient(
            verify=verify_ssl,
            limits=limits,
            timeout=timeout,
            follow_redirects=True,
        ) as client:
            response = await client.get(url)

        headers = {k.lower(): v for k, v in response.headers.items()}
        # Enforce 5MB payload limit
        body_bytes = response.content[:_MAX_SCRIPT_BYTES]
        body = body_bytes.decode("utf-8", errors="replace")
        return headers, body
