"""
app/scanners/dns/query.py

Performs asynchronous DNS record queries using dnspython.
Supports custom resolvers, PTR reverse DNS lookups, and response status metadata.
"""

import dns.asyncresolver
import dns.exception
import dns.reversename
import dns.resolver

from app.scanners.base.exceptions import ScannerConnectionError, ScannerTimeoutError
from app.scanners.dns.models import DnsRecord
from app.scanners.dns.parser import parse_dns_rdata


async def query_dns_record(
    target: str,
    rtype: str,
    timeout: float = 5.0,
    nameservers: list[str] | None = None,
) -> list[DnsRecord]:
    """
    Asynchronously query a specific record type for a domain or IP target.
    
    Args:
        target: Normalized domain name or IP address.
        rtype: Record type (A, AAAA, MX, TXT, PTR, etc.).
        timeout: Configuration query timeout in seconds.
        nameservers: Optional custom DNS resolver IP addresses list.
        
    Returns:
        List of parsed DnsRecord models.
        
    Raises:
        ScannerTimeoutError: If the DNS resolver query times out.
        ScannerConnectionError: If no nameservers respond or DNS resolution fails.
    """
    resolver = dns.asyncresolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    if nameservers:
        resolver.nameservers = nameservers
    else:
        # Include Google and Cloudflare DNS to prevent local system DNS timeouts
        default_ns = list(resolver.nameservers)
        fallback_ns = ["8.8.8.8", "1.1.1.1", "8.8.4.4"]
        resolver.nameservers = [ns for ns in default_ns if ns not in ("127.0.0.1", "::1")] + fallback_ns

    # Reverse DNS PTR target formatting
    query_target = target
    if rtype.upper() == "PTR":
        try:
            rev_name = dns.reversename.from_address(target)
            query_target = str(rev_name)
        except Exception:
            # Target is already a domain or pointer string
            pass

    try:
        # Perform async query
        answer = await resolver.resolve(query_target, rtype)
        ttl = int(answer.ttl)
        rcode_str = dns.rcode.to_text(answer.response.rcode())

        records = []
        for rdata in answer:
            parsed = parse_dns_rdata(rtype, rdata, ttl)
            if parsed is not None:
                parsed.extra["dns_status"] = rcode_str
                records.append(parsed)
        return records

    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        # NXDOMAIN: Domain does not exist (valid empty response from scanner perspective)
        # NoAnswer: Domain exists but has no record of this type
        return []

    except dns.exception.Timeout:
        # Resolve timeout
        raise ScannerTimeoutError(
            f"DNS query for '{target}' type '{rtype}' timed out after {timeout}s."
        )

    except dns.resolver.NoNameservers:
        # Nameservers not responding or network down
        raise ScannerConnectionError(
            f"No nameservers responded during DNS query for '{target}' type '{rtype}'."
        )

    except dns.exception.DNSException as e:
        # Other general dnspython resolution exceptions
        raise ScannerConnectionError(
            f"DNS error resolving '{target}' type '{rtype}': {e}"
        )
