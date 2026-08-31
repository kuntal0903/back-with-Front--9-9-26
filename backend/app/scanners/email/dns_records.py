"""
app/scanners/email/dns_records.py

Asynchronously queries DNS MX, SPF, DKIM, DMARC, TLS-RPT records,
resolves mail host A/AAAA IPs, and queries MTA-STS HTTP endpoints.
"""

import asyncio
import dns.asyncresolver
import dns.exception
import dns.resolver
import httpx


async def query_mx_exchanges(domain: str, timeout: float = 3.0) -> tuple[str, list[tuple[int, str]]]:
    """
    Query MX records for the given apex domain.
    
    Returns:
        tuple[str, list[tuple[int, str]]]:
            - dns_status: VALID_MX | NO_MX_RECORD | NXDOMAIN | SERVFAIL | TIMEOUT | DNS_ERROR
            - list of (priority, exchange_hostname) tuples.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        answer = await resolver.resolve(domain, "MX")
        exchanges = []
        for rdata in sorted(answer, key=lambda r: int(r.preference)):
            ex_host = str(rdata.exchange).rstrip(".").lower()
            exchanges.append((int(rdata.preference), ex_host))
        if exchanges:
            return "VALID_MX", exchanges
        return "NO_MX_RECORD", []
    except dns.resolver.NoAnswer:
        return "NO_MX_RECORD", []
    except dns.resolver.NXDOMAIN:
        return "NXDOMAIN", []
    except dns.resolver.NoNameservers:
        return "SERVFAIL", []
    except dns.exception.Timeout:
        return "TIMEOUT", []
    except Exception:
        return "DNS_ERROR", []


async def resolve_mail_host(hostname: str, timeout: float = 3.0) -> tuple[list[str], list[str], list[str]]:
    """
    Resolve A (IPv4) and AAAA (IPv6) addresses for an MX hostname, and lookup PTR records.
    
    Returns:
        tuple[list[str], list[str], list[str]]:
            - ipv4_addresses
            - ipv6_addresses
            - ptr_records
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    ipv4s = []
    ipv6s = []
    ptrs = []

    # 1. Resolve A (IPv4)
    try:
        ans_a = await resolver.resolve(hostname, "A")
        for rdata in ans_a:
            ipv4s.append(str(rdata).strip())
    except Exception:
        pass

    # 2. Resolve AAAA (IPv6)
    try:
        ans_aaaa = await resolver.resolve(hostname, "AAAA")
        for rdata in ans_aaaa:
            ipv6s.append(str(rdata).strip())
    except Exception:
        pass

    # 3. PTR lookup for resolved IPs
    for ip in (ipv4s + ipv6s)[:3]:
        try:
            rev_name = dns.reversename.from_address(ip)
            ans_ptr = await resolver.resolve(rev_name, "PTR")
            for rdata in ans_ptr:
                ptrs.append(str(rdata).rstrip(".").lower())
        except Exception:
            pass

    return ipv4s, ipv6s, ptrs


async def query_txt_records(domain: str, timeout: float = 3.0) -> list[str]:
    """
    Query raw TXT records on the given domain target.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout

    try:
        answer = await resolver.resolve(domain, "TXT")
        records = []
        for rdata in answer:
            records.append("".join(str(s, "utf-8") if isinstance(s, bytes) else str(s) for s in rdata.strings))
        return records
    except Exception:
        return []


async def query_dkim_record(selector: str, domain: str, timeout: float = 3.0) -> str | None:
    """
    Query TXT record at selector._domainkey.domain.
    """
    target = f"{selector}._domainkey.{domain}"
    records = await query_txt_records(target, timeout)

    for record in records:
        if record.strip().lower().startswith(("v=dkim1", "p=")):
            return record.strip()

    return None


async def query_mta_sts_policy(domain: str, timeout: float = 3.0) -> tuple[int | None, str | None]:
    """
    Fetch MTA-STS policy via HTTPS request to https://mta-sts.<domain>/.well-known/mta-sts.txt.
    """
    url = f"https://mta-sts.{domain}/.well-known/mta-sts.txt"
    try:
        async with httpx.AsyncClient(verify=False, timeout=timeout, follow_redirects=True) as client:
            response = await client.get(url)
            return response.status_code, response.text
    except Exception:
        return None, None


async def query_tls_rpt_record(domain: str, timeout: float = 3.0) -> list[str]:
    """
    Query TXT record at _smtp._tls.domain.
    """
    target = f"_smtp._tls.{domain}"
    return await query_txt_records(target, timeout)
