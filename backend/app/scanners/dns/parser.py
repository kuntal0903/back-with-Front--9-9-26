"""
app/scanners/dns/parser.py

Parses raw dnspython lookup data into structured DnsRecord models.
"""

from typing import Any

from app.scanners.dns.models import DnsRecord


def parse_dns_rdata(rtype: str, rdata: Any, ttl: int) -> DnsRecord | None:
    """
    Parse a single dnspython resource record into a DnsRecord model.
    
    Args:
        rtype: The record type string (A, AAAA, CNAME, etc.).
        rdata: The raw dnspython rdata object.
        ttl: Time to live duration.
        
    Returns:
        DnsRecord model if parsed successfully, otherwise None.
    """
    rtype = rtype.upper()
    val = ""
    preference = None
    extra = {}

    try:
        if rtype in ("A", "AAAA"):
            # dnspython: rdata has an 'address' attribute
            val = str(rdata.address)

        elif rtype in ("CNAME", "NS", "PTR"):
            # dnspython: rdata has a 'target' attribute (Name object)
            val = str(rdata.target).rstrip(".")

        elif rtype == "MX":
            # dnspython: rdata has 'exchange' (Name object) and 'preference' (int)
            val = str(rdata.exchange).rstrip(".")
            preference = int(rdata.preference)

        elif rtype == "TXT":
            # dnspython: rdata has a 'strings' attribute (tuple of bytes)
            # TXT records can contain multiple chunks of strings that should be concatenated
            chunks = [chunk.decode("utf-8", errors="ignore") for chunk in rdata.strings]
            val = "".join(chunks)

        elif rtype == "SOA":
            # dnspython: rdata has mname, rname, serial, refresh, retry, expire, minimum
            val = str(rdata.mname).rstrip(".")
            extra = {
                "rname": str(rdata.rname).rstrip("."),
                "serial": int(rdata.serial),
                "refresh": int(rdata.refresh),
                "retry": int(rdata.retry),
                "expire": int(rdata.expire),
                "minimum": int(rdata.minimum),
            }

        elif rtype == "CAA":
            # dnspython: rdata has flags, tag (bytes), value (bytes)
            tag = rdata.tag.decode("utf-8", errors="ignore") if isinstance(rdata.tag, bytes) else str(rdata.tag)
            value = rdata.value.decode("utf-8", errors="ignore") if isinstance(rdata.value, bytes) else str(rdata.value)
            val = f"{rdata.flags} {tag} {value}"
            extra = {
                "flags": int(rdata.flags),
                "tag": tag,
                "value": value,
            }
        else:
            # Catch-all fallback for other types
            val = str(rdata)

    except Exception:
        # Failed to parse specific fields; return None to avoid reporting bad records
        return None

    return DnsRecord(
        record_type=rtype,
        value=val,
        ttl=ttl,
        preference=preference,
        extra=extra,
    )
