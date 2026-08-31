"""
app/scanners/email/validator.py

Parses and validates syntax formats, mechanisms, duplicates, and policies for
SPF, DMARC, DKIM, MTA-STS, and TLS-RPT records.
"""

import re
from app.scanners.email.models import (
    DkimDetails,
    DkimSelectorResult,
    DmarcDetails,
    MtaStsDetails,
    SpfDetails,
    TlsRptDetails,
)

# RFC 7208 maximum allowed DNS lookups for SPF mechanisms
_MAX_SPF_DNS_LOOKUPS = 10


def validate_spf_records(txt_records: list[str]) -> SpfDetails:
    """
    Filter, parse mechanisms, and validate SPF records from apex TXT records.
    """
    spf_records = [r.strip() for r in txt_records if r.strip().lower().startswith("v=spf1")]

    if not spf_records:
        return SpfDetails(record_found=False, strength="none")

    details = SpfDetails(
        record_found=True,
        records=spf_records,
        is_valid=True,
        has_duplicates=len(spf_records) > 1,
    )

    if details.has_duplicates:
        details.is_valid = False
        details.errors.append("Multiple SPF records found. This is invalid per RFC 7208.")
        details.strength = "none"
        return details

    spf_record = spf_records[0]
    tokens = spf_record.split()

    if not tokens[0].lower().startswith("v=spf1"):
        details.is_valid = False
        details.errors.append("SPF record must start exactly with 'v=spf1'.")
        return details

    mechanisms = []
    includes = []
    redirect = None
    all_token = None
    dns_lookup_count = 0

    for token in tokens[1:]:
        token_clean = token.strip()
        token_lower = token_clean.lower()

        if token_lower.endswith("all"):
            all_token = token_lower
            mechanisms.append(token_clean)
            continue

        if token_lower.startswith("include:"):
            inc_domain = token_clean.split(":", 1)[1].strip()
            includes.append(inc_domain)
            mechanisms.append(token_clean)
            dns_lookup_count += 1
        elif token_lower.startswith("redirect="):
            redirect = token_clean.split("=", 1)[1].strip()
            mechanisms.append(token_clean)
            dns_lookup_count += 1
        elif token_lower.startswith(("ip4:", "ip6:")):
            mechanisms.append(token_clean)
        elif token_lower in ("a", "mx", "ptr") or token_lower.startswith(("a:", "mx:", "ptr:", "exists:")):
            mechanisms.append(token_clean)
            dns_lookup_count += 1
        else:
            mechanisms.append(token_clean)

    details.mechanisms = mechanisms
    details.includes = includes
    details.redirect = redirect
    details.lookup_count = dns_lookup_count
    details.is_truncated = dns_lookup_count > _MAX_SPF_DNS_LOOKUPS

    if details.is_truncated:
        details.warnings.append(
            f"SPF record contains {dns_lookup_count} DNS lookups, exceeding the RFC 7208 limit of {_MAX_SPF_DNS_LOOKUPS}."
        )

    if all_token:
        details.policy_qualifier = all_token
        if all_token in ("-all", "~all"):
            details.strength = "strong"
        elif all_token in ("+all", "?all", "all"):
            details.strength = "weak"
            details.warnings.append(f"Insecure SPF 'all' qualifier '{all_token}' allows wide unauthorized mailing.")
        else:
            details.strength = "weak"
            details.warnings.append(f"Unknown SPF 'all' qualifier format '{all_token}'.")
    else:
        details.strength = "weak"
        details.warnings.append("No explicit 'all' mechanism specified. Default policy behaves weakly.")

    return details


def validate_dmarc_records(txt_records: list[str]) -> DmarcDetails:
    """
    Filter, parse tags, and validate DMARC records from _dmarc TXT records.
    """
    dmarc_records = [r.strip() for r in txt_records if r.strip().lower().startswith("v=dmarc1")]

    if not dmarc_records:
        return DmarcDetails(record_found=False, policy="none")

    details = DmarcDetails(
        record_found=True,
        records=dmarc_records,
        is_valid=True,
        has_duplicates=len(dmarc_records) > 1,
    )

    if details.has_duplicates:
        details.is_valid = False
        details.errors.append("Multiple DMARC records found. This is invalid per RFC 7489.")
        return details

    dmarc_record = dmarc_records[0]
    tags: dict[str, str] = {}
    parts = dmarc_record.split(";")

    first_part = parts[0].strip().lower()
    if not first_part.startswith("v=dmarc1"):
        details.is_valid = False
        details.errors.append("DMARC record must start with 'v=DMARC1'.")
        return details

    for part in parts[1:]:
        part = part.strip()
        if not part or "=" not in part:
            continue
        key_val = part.split("=", 1)
        tags[key_val[0].strip().lower()] = key_val[1].strip()

    # 1. Apex Policy (p)
    p_val = tags.get("p")
    if not p_val:
        details.is_valid = False
        details.errors.append("DMARC record is missing the required policy ('p') tag.")
    else:
        p_lower = p_val.lower().strip()
        if p_lower in ("none", "quarantine", "reject"):
            details.policy = p_lower
            if p_lower == "none":
                details.warnings.append("DMARC policy 'p=none' runs in monitoring mode only, offering no spoofing block.")
        else:
            details.is_valid = False
            details.errors.append(f"Invalid DMARC policy value 'p={p_val}'. Supported values: none, quarantine, reject.")

    # 2. Subdomain Policy (sp)
    sp_val = tags.get("sp")
    if sp_val:
        sp_lower = sp_val.lower().strip()
        if sp_lower in ("none", "quarantine", "reject"):
            details.subdomain_policy = sp_lower

    # 3. Percentage (pct)
    pct_val = tags.get("pct")
    if pct_val:
        try:
            pct_int = int(pct_val)
            if 0 <= pct_int <= 100:
                details.percentage = pct_int
            else:
                details.is_valid = False
                details.errors.append(f"DMARC pct tag value '{pct_val}' must be an integer between 0 and 100.")
        except ValueError:
            details.is_valid = False
            details.errors.append(f"DMARC pct tag value '{pct_val}' is not a valid integer.")

    # 4. Alignment tags (adkim, aspf)
    if "adkim" in tags:
        details.alignment_dkim = tags["adkim"].lower().strip()
    if "aspf" in tags:
        details.alignment_spf = tags["aspf"].lower().strip()

    # 5. Report interval (ri) & failure options (fo)
    if "ri" in tags:
        try:
            details.report_interval = int(tags["ri"])
        except ValueError:
            pass
    if "fo" in tags:
        details.failure_options = tags["fo"]

    # 6. Aggregate (rua) and Forensic (ruf) URIs
    if "rua" in tags:
        details.aggregate_reports = [uri.strip() for uri in tags["rua"].split(",") if uri.strip()]
    else:
        details.warnings.append("No DMARC aggregate reporting (rua) target URI configured.")

    if "ruf" in tags:
        details.forensic_reports = [uri.strip() for uri in tags["ruf"].split(",") if uri.strip()]

    return details


def parse_dkim_selector_record(selector: str, raw_record: str) -> DkimSelectorResult:
    """
    Parse tags inside a discovered DKIM selector TXT record.
    """
    tags: dict[str, str] = {}
    parts = raw_record.split(";")

    for part in parts:
        part = part.strip()
        if not part or "=" not in part:
            continue
        kv = part.split("=", 1)
        tags[kv[0].strip().lower()] = kv[1].strip()

    v_val = tags.get("v")
    k_val = tags.get("k", "rsa").lower()
    p_val = tags.get("p")

    is_valid = p_val is not None and len(p_val) > 0

    return DkimSelectorResult(
        selector=selector,
        raw_record=raw_record,
        version=v_val,
        key_type=k_val,
        public_key=p_val,
        is_valid=is_valid,
    )


def validate_mta_sts_policy(status_code: int | None, content: str | None) -> MtaStsDetails:
    """
    Parse key-value lines inside an MTA-STS policy document.
    """
    if status_code != 200 or not content:
        return MtaStsDetails(found=False, status_code=status_code)

    details = MtaStsDetails(found=True, status_code=status_code)
    lines = content.splitlines()

    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        k, v = line.split(":", 1)
        key = k.strip().lower()
        val = v.strip()

        if key == "version":
            details.version = val
        elif key == "mode":
            details.mode = val.lower()
        elif key == "mx":
            details.mx_patterns.append(val)
        elif key == "max_age":
            try:
                details.max_age = int(val)
            except ValueError:
                pass

    return details


def validate_tls_rpt_record(txt_records: list[str]) -> TlsRptDetails:
    """
    Filter and parse TLS-RPT records from _smtp._tls TXT records.
    """
    rpt_records = [r.strip() for r in txt_records if r.strip().lower().startswith("v=tlsrpt1")]

    if not rpt_records:
        return TlsRptDetails(found=False)

    record = rpt_records[0]
    tags: dict[str, str] = {}
    for part in record.split(";"):
        part = part.strip()
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()

    rua_uris = []
    if "rua" in tags:
        rua_uris = [u.strip() for u in tags["rua"].split(",") if u.strip()]

    return TlsRptDetails(
        found=True,
        record=record,
        policy=tags.get("v", "TLSRPT1"),
        report_destinations=rua_uris,
    )
