"""
app/scanners/tech/fingerprinter.py

Evaluates HTTP response components against the technology signatures database.
Parses headers, meta tags, script/stylesheet paths, cookies, and HTML DOM structures.
"""

import re
from typing import Any, Sequence

from app.scanners.tech.models import DetectedTech, TechEvidence
from app.scanners.tech.rules import SIGNATURES, TechSignature

# Regexes for HTML attribute extractions
_META_TAG_PATTERN = re.compile(
    r"<meta\s+[^>]*?(?:name|property|http-equiv)\s*=\s*[\"']([^\"']+)[\"'][^>]*?content\s*=\s*[\"']([^\"']*)[\"']",
    re.IGNORECASE,
)
_META_TAG_PATTERN_ALT = re.compile(
    r"<meta\s+[^>]*?content\s*=\s*[\"']([^\"']*)[\"'][^>]*?(?:name|property|http-equiv)\s*=\s*[\"']([^\"']+)[\"']",
    re.IGNORECASE,
)
_SCRIPT_SRC_PATTERN = re.compile(r"<script\s+[^>]*?src\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_LINK_HREF_PATTERN = re.compile(r"<link\s+[^>]*?href\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)
_ASSET_SRC_PATTERN = re.compile(r"<(?:img|source)\s+[^>]*?src\s*=\s*[\"']([^\"']+)[\"']", re.IGNORECASE)


def parse_html_elements(html_body: str) -> tuple[dict[str, str], list[str], list[str], list[str]]:
    """
    Extract meta tags, script srcs, stylesheet hrefs, and static asset paths from HTML.
    
    Returns:
        tuple containing:
            - meta_tags: dict[lowercase_name, content]
            - script_srcs: list[str]
            - stylesheet_hrefs: list[str]
            - asset_paths: list[str]
    """
    meta_tags = {}
    for match in _META_TAG_PATTERN.finditer(html_body):
        name = match.group(1).lower().strip()
        content = match.group(2).strip()
        meta_tags[name] = content

    for match in _META_TAG_PATTERN_ALT.finditer(html_body):
        name = match.group(2).lower().strip()
        content = match.group(1).strip()
        if name not in meta_tags:
            meta_tags[name] = content

    script_srcs = [m.group(1).strip() for m in _SCRIPT_SRC_PATTERN.finditer(html_body)]
    stylesheet_hrefs = [m.group(1).strip() for m in _LINK_HREF_PATTERN.finditer(html_body)]
    asset_paths = [m.group(1).strip() for m in _ASSET_SRC_PATTERN.finditer(html_body)]

    return meta_tags, script_srcs, stylesheet_hrefs, asset_paths


def fingerprint_response(
    headers: dict[str, str],
    html_body: str,
    cookies: Sequence[str],
    script_srcs: Sequence[str] | None = None,
    stylesheet_hrefs: Sequence[str] | None = None,
    asset_paths: Sequence[str] | None = None,
) -> list[DetectedTech]:
    """
    Match HTTP response attributes against multi-signal signature rules to identify technologies.
    
    Args:
        headers: Dict of lowercase header keys and values.
        html_body: Decoded HTML string of the body payload.
        cookies: Sequence of cookie names or Set-Cookie strings.
        script_srcs: Optional pre-parsed script URLs.
        stylesheet_hrefs: Optional pre-parsed stylesheet URLs.
        asset_paths: Optional pre-parsed asset paths.
        
    Returns:
        list[DetectedTech]: Discovered technologies with complete evidence and confidence ratings.
    """
    detected_list = []
    body = html_body.strip()
    lowercase_headers = {k.lower(): str(v) for k, v in headers.items()}
    cookie_names = [c.strip() for c in cookies]

    # Extract HTML metadata if not explicitly supplied
    parsed_metas, parsed_scripts, parsed_styles, parsed_assets = parse_html_elements(body)

    scripts_to_check = list(script_srcs) if script_srcs is not None else parsed_scripts
    styles_to_check = list(stylesheet_hrefs) if stylesheet_hrefs is not None else parsed_styles
    assets_to_check = list(asset_paths) if asset_paths is not None else parsed_assets

    for sig in SIGNATURES:
        evidence_list: list[TechEvidence] = []
        version = None

        # 0. Check Negative Indicators
        is_negated = False
        for neg_pat in sig.negative_indicators:
            if neg_pat.search(body):
                is_negated = True
                break
            for hval in lowercase_headers.values():
                if neg_pat.search(hval):
                    is_negated = True
                    break
            if is_negated:
                break

        if is_negated:
            continue

        # 1. Match HTTP Response Headers
        for hname, hpattern in sig.headers.items():
            if hname in lowercase_headers:
                hval = lowercase_headers[hname]
                if hpattern.search(hval):
                    evidence_list.append(
                        TechEvidence(
                            type="http_header",
                            source=f"header:{hname}",
                            value=hval,
                            indicator_pattern=hpattern.pattern,
                        )
                    )
                    # Check version parser against header value
                    for vparser in sig.version_parsers:
                        vmatch = vparser.search(hval)
                        if vmatch and vmatch.lastindex and vmatch.group(1):
                            version = vmatch.group(1)

        # 2. Match HTML Meta Tags
        for mname, mpattern in sig.meta_patterns.items():
            if mname in parsed_metas:
                mval = parsed_metas[mname]
                if mpattern.search(mval):
                    evidence_list.append(
                        TechEvidence(
                            type="meta_tag",
                            source=f"meta:{mname}",
                            value=mval,
                            indicator_pattern=mpattern.pattern,
                        )
                    )
                    # Check version parser against meta tag content
                    for vparser in sig.version_parsers:
                        vmatch = vparser.search(mval)
                        if vmatch and vmatch.lastindex and vmatch.group(1):
                            version = vmatch.group(1)
                    # Also try extracting capture group directly from mpattern
                    m_direct_match = mpattern.search(mval)
                    if m_direct_match and m_direct_match.lastindex and m_direct_match.group(1):
                        version = m_direct_match.group(1)

        # 3. Match Script References
        for spattern in sig.script_patterns:
            for s_url in scripts_to_check:
                if spattern.search(s_url):
                    evidence_list.append(
                        TechEvidence(
                            type="script_src",
                            source="script:src",
                            value=s_url,
                            indicator_pattern=spattern.pattern,
                        )
                    )
                    for vparser in sig.version_parsers:
                        vmatch = vparser.search(s_url)
                        if vmatch and vmatch.lastindex and vmatch.group(1):
                            version = vmatch.group(1)

        # 4. Match Stylesheet References
        for stpattern in sig.style_patterns:
            for st_url in styles_to_check:
                if stpattern.search(st_url):
                    evidence_list.append(
                        TechEvidence(
                            type="stylesheet_href",
                            source="stylesheet:href",
                            value=st_url,
                            indicator_pattern=stpattern.pattern,
                        )
                    )
                    for vparser in sig.version_parsers:
                        vmatch = vparser.search(st_url)
                        if vmatch and vmatch.lastindex and vmatch.group(1):
                            version = vmatch.group(1)

        # 5. Match Static Asset Paths
        for apattern in sig.asset_patterns:
            for a_path in assets_to_check:
                if apattern.search(a_path):
                    evidence_list.append(
                        TechEvidence(
                            type="asset_path",
                            source="asset:path",
                            value=a_path,
                            indicator_pattern=apattern.pattern,
                        )
                    )

        # 6. Match Cookie Metadata
        for cpattern in sig.cookies:
            for cname in cookie_names:
                if cpattern.search(cname):
                    evidence_list.append(
                        TechEvidence(
                            type="cookie_name",
                            source="cookie:name",
                            value=cname,
                            indicator_pattern=cpattern.pattern,
                        )
                    )

        # 7. Match HTML & DOM Patterns
        for dpattern in sig.dom_patterns:
            if dpattern.search(body):
                evidence_list.append(
                    TechEvidence(
                        type="dom_pattern",
                        source="html:body",
                        value=dpattern.pattern,
                        indicator_pattern=dpattern.pattern,
                    )
                )

        for hpattern in sig.html_patterns:
            if hpattern.search(body):
                evidence_list.append(
                    TechEvidence(
                        type="html_pattern",
                        source="html:body",
                        value=hpattern.pattern,
                        indicator_pattern=hpattern.pattern,
                    )
                )
                for vparser in sig.version_parsers:
                    vmatch = vparser.search(body)
                    if vmatch and vmatch.lastindex and vmatch.group(1):
                        version = vmatch.group(1)

        # If any evidence was matched for this technology signature
        if evidence_list:
            # Deduplicate evidence objects by (type, source, value)
            seen_keys = set()
            deduped_evidence: list[TechEvidence] = []
            for ev in evidence_list:
                key = (ev.type, ev.source, ev.value)
                if key not in seen_keys:
                    seen_keys.add(key)
                    deduped_evidence.append(ev)

            # Determine explicit detection methods used
            detection_methods = sorted(list(set(ev.type for ev in deduped_evidence)))
            
            # Format matched_indicators for backwards compatibility
            matched_indicators = []
            for ev in deduped_evidence:
                if ev.type == "http_header":
                    matched_indicators.append(ev.source)
                elif ev.type == "cookie_name":
                    matched_indicators.append(f"cookie:{ev.value}")
                elif ev.type in ("html_pattern", "dom_pattern"):
                    matched_indicators.append(f"html:{ev.value}")
                else:
                    matched_indicators.append(f"{ev.source}={ev.value}")

            # ─── DETERMINISTIC CONFIDENCE ENGINE ───
            # High Confidence: Meta generator match OR evidence across 2+ distinct categories OR explicit high default with 2+ indicators
            meta_match = any(ev.type == "meta_tag" for ev in deduped_evidence)
            multi_source = len(detection_methods) >= 2
            
            if meta_match or multi_source or (sig.confidence_default == "high" and len(deduped_evidence) >= 2):
                confidence = "high"
            elif len(deduped_evidence) >= 1 and sig.confidence_default in ("high", "medium"):
                confidence = "medium"
            else:
                confidence = "low"

            detected_list.append(
                DetectedTech(
                    name=sig.name,
                    category=sig.category,
                    version=version,
                    status="detected",
                    confidence=confidence,
                    evidence=deduped_evidence,
                    detection_methods=detection_methods,
                    matched_indicators=matched_indicators,
                )
            )

    return detected_list
