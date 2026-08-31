# Verification.md — Technical Verification Matrix

This document provides the authoritative verification matrix and technical proof for:
1. **Domain Scan / DNS Discovery**
2. **Port Discovery**
3. **Service Identification**
4. **HTTP / HTTPS Scanner**
5. **Technology Detection**
6. **Web Endpoint Discovery**
7. **JavaScript Discovery**
8. **Live TLS Scan**
9. **Email Security Scan**
10. **Advanced Cloud/CDN Detection**

---

## 1. Service Identification Verification Matrix

| Information Category | Probing Method | Receiver | Response Parser | Validator | Technical Evidence | Confidence Level |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **SSH Protocol** | TCP Socket Greeting Read | Target IP / Port 22 | `protocols/ssh.py` | `_SSH_PATTERN` regex match | Raw SSH identification string | `high` |
| **SMTP Protocol** | TCP Socket Greeting Read | Target IP / Port 25, 465, 587 | `protocols/smtp.py` | `_SMTP_PATTERN` (220 greeting) | Raw SMTP banner greeting | `high` |
| **FTP Protocol** | TCP Socket Greeting Read | Target IP / Port 21 | `protocols/ftp.py` | `_FTP_PATTERN` (220 greeting) | Raw FTP banner greeting | `high` |
| **HTTP / HTTPS** | Async HEAD/GET + TLS Handshake | Target IP / Port 80, 443, 8080 | `protocols/http.py` | `parse_http_response_banner` | HTTP Status line & Server header | `high` |
| **TLS-Wrapped Service** | Asynchronous `ssl.create_default_context` | Target IP / Port | `protocols/tls.py` | `check_tls_wrapper` | Negotiated TLS ALPN & cipher | `high` |
| **Generic TCP Service** | TCP Socket Probe Read | Target IP / Port | `protocols/generic.py` | Conservative fallback | Cleansed raw greeting payload | `low` / `medium` |

---

## 2. HTTP / HTTPS Scanner Verification Matrix

| Information Category | Request Mechanism | Response Field / Source | Response Parser | Technical Evidence | Transport vs HTTP Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **HTTP Status Code** | HTTP GET via `httpx.AsyncClient` | Response Status Line | `response.status_code` | Status code (e.g. 200, 301, 403) | `transport_status: "success"` |
| **HTML Page Title** | Streaming Response Body Read | HTML `<title>` tag | `parse_page_title()` | Unescaped page title string | `title: null` if absent |
| **Server Product & Version** | Response Headers | `Server:` header | `parse_server_header()` | `server_product` & `server_version` | `server_version: null` if missing |
| **Security Headers** | Response Headers | Security headers | `parse_security_headers()` | HSTS, CSP, X-Frame-Options | Recorded as observed config |
| **Cookie Attributes** | Set-Cookie Response Headers | `Set-Cookie:` header | `parse_cookies_metadata()` | Cookie name, domain, path, secure, httponly | No credential values stored |
| **Redirect Chain** | Chronological Redirect Loop | Response History | `response.history` | Chain step URLs & status codes | Bounded by max redirects limit |
| **Response Size Protection** | `client.stream()` Async Iteration | Raw Response Body | 5MB hard limit cutoff | `body_size_bytes` | Prevents decompression bombs |

---

## 3. Technology Detection Verification Matrix

| Information Category | Evidence Source | Parser / Extractor | Validator & Fingerprint Engine | Technical Evidence | Confidence Rule |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **HTTP Headers** | Response Headers | `fingerprinter.py` | `headers` dict regex matching | `header:<name>` value | `medium` / `high` |
| **HTML Meta Generator** | HTML `<meta>` tags | `parse_html_elements()` | `meta_patterns` regex matching | `meta:generator` content string | `high` |
| **Script References** | `<script src="...">` | `parse_html_elements()` | `script_patterns` regex matching | `script:src` URL string | `medium` / `high` |
| **Stylesheet References** | `<link href="...">` | `parse_html_elements()` | `style_patterns` regex matching | `stylesheet:href` URL string | `medium` / `high` |
| **Static Asset Paths** | `<img/source src="...">` | `parse_html_elements()` | `asset_patterns` regex matching | `asset:path` URL string | `medium` / `high` |
| **Cookie Metadata** | Set-Cookie / Cookie names | `fingerprinter.py` | `cookies` pattern matching | `cookie:name` string | `medium` / `high` |
| **DOM Structural Markers** | HTML DOM attributes | `fingerprinter.py` | `dom_patterns` regex matching | `dom_pattern` string | `high` |

---

## 4. Web Endpoint Discovery Verification Matrix

| Information Category | Discovery Source | Parser / Extractor | Normalizer & Validator | Technical Evidence | Discovery Status |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Web Pages** | HTML `<a href="...">` | `extract_html_resources()` | `normalize_url()` + `is_url_in_scope()` | Contacted response status & content type | `VERIFIED_LIVE` |
| **HTML Forms** | `<form action>` & inputs | `parse_html_forms()` | `normalize_url()` + parameter extraction | Action URL, method, input names & types | `DISCOVERED` |
| **Script Resources** | `<script src="...">` | `extract_html_resources()` | `normalize_url()` | Script asset URL & path | `DISCOVERED` |
| **Stylesheets & Icons** | `<link href="...">` | `extract_html_resources()` | `normalize_url()` | Stylesheet asset URL & path | `DISCOVERED` |
| **robots.txt Directives** | `/robots.txt` GET | `parse_robots_txt()` | Path normalization | Disallow/Allow paths & Sitemap URLs | `DISCOVERED` / `VERIFIED_LIVE` |
| **sitemap.xml Locations** | `/sitemap.xml` GET | `parse_sitemap_xml()` | XML `<loc>` extraction & normalization | Sitemap page locations | `DISCOVERED` / `VERIFIED_LIVE` |

---

## 5. JavaScript Discovery Verification Matrix

| Information Category | Source | Method | Evidence | Validation & Status |
| :--- | :--- | :--- | :--- | :--- |
| **Absolute URLs** | JS source code | `extract_js_references()` | `_ABSOLUTE_URL_PATTERN` match | URL parser (`status: REFERENCED`) |
| **Relative REST Paths** | JS source code | `extract_js_references()` | `_RELATIVE_PATH_PATTERN` match | Resolved against origin page (`status: REFERENCED`) |
| **WebSocket Endpoints** | JS source code | `extract_js_references()` | `_WEBSOCKET_URL_PATTERN` match | `ws://` or `wss://` URL parser (`status: REFERENCED`) |
| **Request Patterns** | JS source code | `extract_js_references()` | `_FETCH_PATTERN` / `AXIOS` / `AJAX` | HTTP method & target URL (`status: REFERENCED`) |
| **Template Literals** | JS source code | `extract_js_references()` | `_TEMPLATE_LITERAL_PATTERN` | Expression string (`status: partially_resolved`) |
| **Source Maps** | JS file / header | `extract_js_references()` | `_SOURCEMAP_PATTERN` match | `sourceMappingURL` reference (`status: REFERENCED`) |
| **Library Banners** | JS source comments | `extract_js_references()` | `_LIBRARY_BANNER_PATTERN` | Explicit version string (`status: REFERENCED`) |

---

## 6. Live TLS Scan Verification Matrix

| Information Category | Source | Method | Evidence | Validation |
| :--- | :--- | :--- | :--- | :--- |
| **TLS Version** | TLS Handshake | `execute_tls_handshake()` | `ssock.version()` | Negotiated protocol string |
| **Cipher Suite** | TLS Handshake | `execute_tls_handshake()` | `ssock.cipher()` | Negotiated cipher suite name |
| **ALPN Protocol** | TLS Handshake | `execute_tls_handshake()` | `ssock.selected_alpn_protocol()` | `h2` / `http/1.1` / `none` |
| **Peer Certificate** | TLS Handshake | `parse_der_certificate()` | Binary DER peer certificate | Decoded ASN.1 subject & issuer RDNs |
| **SHA-256 Fingerprint** | Peer Certificate | `parse_der_certificate()` | `hashlib.sha256(der_bytes)` | 64-character hex fingerprint |
| **SAN Entries** | Peer Certificate | `parse_der_certificate()` | `subjectAltName` extension | Extracted DNS names & IPs |
| **Hostname Verification**| Target Host vs Cert | `evaluate_hostname_verification()`| CN & SAN pattern matching | `valid` vs `mismatch` |
| **Trust Status** | Target Host vs Cert | `evaluate_trust_status()` | Expiry date, self-signed, host match | `valid` / `expired` / `self_signed` / `hostname_mismatch` |

---

## 7. Email Security Scan Verification Matrix

| Information Category | Source | Method | Evidence | Validation |
| :--- | :--- | :--- | :--- | :--- |
| **MX Host Resolution** | DNS MX + A/AAAA | `query_mx_exchanges()` + `resolve_mail_host()` | Preference, host, A/AAAA IPs, PTR | Preserved hostname & IP relationships |
| **SPF Mechanisms & Bounds**| Apex TXT record | `validate_spf_records()` | `ip4`, `include`, `redirect`, `all` | Lookup count tracking (max 10 limit) |
| **DMARC Policy Tags** | `_dmarc` TXT record | `validate_dmarc_records()` | `p`, `sp`, `pct`, `adkim`, `aspf`, `rua`, `ruf` | Policy enforcement validation |
| **DKIM Selectors** | `sel._domainkey` TXT | `parse_dkim_selector_record()` | `v`, `k`, `p`, `t`, `n` tags | Public key presence validation |
| **MTA-STS Policy** | HTTPS `.well-known` | `query_mta_sts_policy()` + validator | `version`, `mode`, `mx`, `max_age` | Status code 200 & key-value parsing |
| **TLS-RPT Record** | `_smtp._tls` TXT | `validate_tls_rpt_record()` | `v=TLSRPT1`, `rua=mailto:...` | Reporting URI parsing |
| **SMTP STARTTLS Probe**| Safe Socket Probe | `probe_smtp_service()` | 220 banner + `EHLO` STARTTLS flag | Non-destructive socket observation |

---

## 8. Advanced Cloud/CDN Detection Verification Matrix

| Information Category | Source | Method | Evidence | Validation & Confidence |
| :--- | :--- | :--- | :--- | :--- |
| **CNAME Chain Analysis** | DNS CNAME query | CNAME recursion up to depth 5 | Observed target alias sequence | CNAME pattern rules |
| **IP/ASN Ownership** | A/AAAA resolution | `find_ip_provider_details()` | Matched CIDR subnet & Organization | `NETWORK_OWNER` classification |
| **HTTP CDN Headers** | HTTP response headers | `analyze_headers_details()` | `cf-ray`, `x-amz-cf-id`, `x-azure-ref`, `via` | Header signature matching |
| **TLS Cert Correlation** | TLS handshake cert | `analyze_tls_certificate()` | Certificate Issuer RDN & SAN domains | Certificate pattern rules |
| **Multi-Signal Engine** | Aggregated signals | `CloudScanner._execute()` | CNAME + Header + Cert + IP Range | `CONFIRMED` (2+ signals) / `LIKELY` |
| **Edge vs Origin IP** | Observed target IP | `CloudScanner._execute()` | Resolved public edge IP | `origin_ip` set to `"unknown"` |

---

---

## 9. Universal Domain + IP Entry Verification Matrix

| Information Category | Request / Input | Processing Method | Intended Receiver | Structured Output | Technical Evidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Domain Entry Flow** | `example.com` | DNS query → A/AAAA/MX/NS/TXT/SOA → IPs/hostnames → Port Discovery → Service ID → HTTP/TLS → Email → Cloud/CDN | DNS Server & Target IP network stack | Enriched `TargetInfo` (type: `domain`), asset graph linkages | DNS responses, TCP probes, HTTP headers, TLS cert SANs |
| **IPv4 Entry Flow** | `192.0.2.10` | Port Discovery + Reverse DNS / PTR → TLS SAN / HTTP redirect hostnames → Domain context → Cloud/CDN | Target IP network stack & TLS server | Enriched `TargetInfo` (type: `ipv4`), hostnames marked `discovered` | TCP open states, PTR answer, TLS certificate SAN |
| **IPv6 Entry Flow** | `2001:db8::10` | Port Discovery + Reverse DNS / PTR → TLS SAN hostnames → Applicable scanners | Target IPv6 network stack | Enriched `TargetInfo` (type: `ipv6`), bracket stripping | IPv6 TCP probes, PTR answer, TLS cert SAN |
| **URL Input Parsing** | `https://example.com:443/path` | `extract_target_components` → host, scheme, port, path → Scope check | Web server | Enriched `TargetInfo` (`scheme: "https"`, `port: 443`, `path: "/path"`) | URL parser, scope validator |
| **IP No-Hostname Flow** | `192.0.2.10` (no PTR/SAN) | Port Discovery → Service ID → HTTP/TLS → Email evaluated to `NOT_APPLICABLE` | Target IP | IP scanners completed; Email = `NOT_APPLICABLE` (no fake domain invented) | Real network response, zero invented domain data |
| **Deduplication History** | Multiple sources (`api.example.com`) | `get_or_create_asset` → UUID5 deterministic ID → `sources` list merged | Asset Graph DB | Single Asset node with `sources: ["dns_scan", "tls_scan", "http_scan", "js_scan"]` | Consolidated evidence history |

---

## 10. Mandatory Negative Verification Rules

1. **No Technology Guessing:** If no explicit fingerprint matches evidence, return empty/unknown. Never guess server or CMS.
2. **Strict Version Extraction:** Software version is recorded ONLY when directly present in headers, meta generator, or versioned asset markers.
3. **No Endpoint Fuzzing:** Only collect endpoints and parameter keys that are actually observed in HTML, forms, scripts, robots.txt, or sitemap.xml.
4. **Live Verification Isolation:** Static URL references extracted from JS or robots.txt are tagged `REFERENCED` / `DISCOVERED` until explicitly verified by a successful live request (`VERIFIED_LIVE`).
5. **Hostname Verification Separation:** Hostname mismatch or trust failure does NOT mean TLS is disabled. Connection and certificate observation are recorded separately from hostname verification.
6. **No Destructive Email Actions:** SMTP observation probes STARTTLS capability without sending emails or authenticating.
7. **No Origin IP Fabrications:** Publicly observed IPs are tagged as `observed_edge_ip`, leaving `origin_ip` as `"unknown"` unless independently verified.
8. **No Invented Domain Names:** Domain-dependent scanners (e.g. Email Security) do NOT invent domain names for IP targets if no PTR, TLS SAN, or HTTP redirect hostname evidence exists.

