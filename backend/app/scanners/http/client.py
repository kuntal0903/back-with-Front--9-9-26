"""
app/scanners/http/client.py

Asynchronously probes HTTP/HTTPS endpoints using httpx AsyncClient.
Handles redirect tracking, timing, response size limits, and SSL verification fallback.
"""

import ssl
import time
import httpx

from app.scanners.base.exceptions import ScannerConnectionError, ScannerTimeoutError
from app.scanners.http.models import HttpDetails, HttpRedirectStep
from app.scanners.http.parser import (
    parse_cookies_metadata,
    parse_page_metadata,
    parse_page_title,
    parse_security_headers,
    parse_server_header,
)

MAX_RESPONSE_SIZE = 5 * 1024 * 1024  # 5MB response size limit
DEFAULT_USER_AGENT = "AttackSurfaceEngine/1.0 (+https://github.com/attack-surface-engine)"


async def probe_http_endpoint(
    url: str,
    timeout: float = 5.0,
    max_redirects: int = 5,
) -> HttpDetails:
    """
    Query an HTTP endpoint, follow redirects, measure timing, and extract content attributes.
    Differentiates transport failures from valid HTTP responses.
    
    Args:
        url: Probed URL string (including scheme).
        timeout: Complete request timeout in seconds.
        max_redirects: Maximum redirections to follow.
        
    Returns:
        HttpDetails: Parsed response metadata model.
    """
    start_time = time.perf_counter()

    # Try with SSL verification enabled first
    try:
        return await _execute_probe(url, timeout, max_redirects, verify_ssl=True)
    except httpx.RequestError as e:
        # Check if the error is caused by SSL verification failure
        err_str = str(e).lower()
        underlying = e.__cause__
        is_ssl_err = "ssl" in err_str or "cert" in err_str
        
        if underlying:
            underlying_str = str(underlying).lower()
            if "ssl" in underlying_str or "cert" in underlying_str or isinstance(underlying, ssl.SSLError):
                is_ssl_err = True

        if is_ssl_err:
            try:
                return await _execute_probe(url, timeout, max_redirects, verify_ssl=False)
            except httpx.TimeoutException:
                duration = time.perf_counter() - start_time
                raise ScannerTimeoutError(f"HTTP request to '{url}' timed out after {timeout}s.")
            except httpx.RequestError as err_exc:
                e = err_exc

        if isinstance(e, httpx.TimeoutException):
            raise ScannerTimeoutError(f"HTTP request to '{url}' timed out after {timeout}s.")
        else:
            raise ScannerConnectionError(f"HTTP connection failed for '{url}': {e}")


try:
    import h2  # type: ignore
    HTTP2_SUPPORTED = True
except ImportError:
    HTTP2_SUPPORTED = False


async def _execute_probe(
    url: str,
    timeout: float,
    max_redirects: int,
    verify_ssl: bool,
) -> HttpDetails:
    """Helper conducting the HTTPX client request and response processing."""
    limits = httpx.Limits(max_keepalive_connections=1, max_connections=2)
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    start_time = time.perf_counter()

    redirect_chain: list[HttpRedirectStep] = []
    set_cookie_headers: list[str] = []

    async with httpx.AsyncClient(
        verify=verify_ssl,
        limits=limits,
        timeout=timeout,
        headers=headers,
        follow_redirects=True,
        max_redirects=max_redirects,
        http2=HTTP2_SUPPORTED,
    ) as client:
        # Stream response to enforce MAX_RESPONSE_SIZE
        async with client.stream("GET", url) as response:
            duration = time.perf_counter() - start_time
            
            # Read response history for redirect chain
            for step in response.history:
                step_headers = {k.lower(): v for k, v in step.headers.items()}
                redirect_chain.append(
                    HttpRedirectStep(
                        url=str(step.url),
                        status_code=step.status_code,
                        headers=step_headers,
                    )
                )

            # Read response content with max size limit
            content_chunks = []
            bytes_read = 0
            async for chunk in response.aiter_bytes():
                bytes_read += len(chunk)
                if bytes_read <= MAX_RESPONSE_SIZE:
                    content_chunks.append(chunk)
                else:
                    # Enforce max body size cutoff
                    break

            body_bytes = b"".join(content_chunks)
            body_text = ""
            try:
                body_text = body_bytes.decode(response.encoding or "utf-8", errors="ignore")
            except Exception:
                pass

            resp_headers = {k.lower(): v for k, v in response.headers.items()}
            
            # Collect set-cookie headers
            for k, v in response.headers.multi_items():
                if k.lower() == "set-cookie":
                    set_cookie_headers.append(v)

            # Extract fields
            server_hdr = resp_headers.get("server")
            server_prod, server_ver = parse_server_header(server_hdr)
            sec_headers = parse_security_headers(resp_headers)
            cookies_meta = parse_cookies_metadata(set_cookie_headers)
            
            content_type = resp_headers.get("content-type")
            title = parse_page_title(body_text) if content_type and "html" in content_type.lower() else parse_page_title(body_text)
            metadata = parse_page_metadata(body_text) if content_type and "html" in content_type.lower() else parse_page_metadata(body_text)

            return HttpDetails(
                url=str(response.url),
                status_code=response.status_code,
                transport_status="success",
                headers=resp_headers,
                http_version=getattr(response, "http_version", "HTTP/1.1"),
                server_product=server_prod,
                server_version=server_ver,
                content_type=content_type,
                title=title,
                body_size_bytes=len(body_bytes),
                redirect_chain=redirect_chain,
                cookies=cookies_meta,
                security_headers=sec_headers,
                metadata=metadata,
                response_time_seconds=duration,
                ssl_verified=verify_ssl,
            )
