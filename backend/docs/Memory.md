# Memory.md
# Attack Surface Engineering Platform — Development State Tracker

**Last Updated:** 2026-08-30
**Document Purpose:** Persistent project state. Read this before starting any development session.

---

## Current Status

**DOMAIN + IP UNIVERSAL SCANNING ARCHITECTURE & TARGET NORMALIZATION ENHANCEMENTS**
**Status:** COMPLETED ✅
**Tests:** 176/176 passed (pytest, Python 3.14.6, 0 failures, 0 warnings)

---

## Summary of Completed Architectural Improvements

### 1. Target Normalizer & URL Handling Engine
- **Universal Target Component Extraction:** Created `extract_target_components` in `normalizer.py` supporting bare domains (`example.com`), hostnames (`api.example.com`), bare IPv4 (`192.0.2.10`), bracketed/bare IPv6 (`[2001:db8::1]`), host:port strings (`192.0.2.10:8080`), and full URLs (`https://example.com:443/path`).
- **Enriched TargetInfo Schema:** Updated `TargetInfo` schema to capture `original`, `normalized`, `target_type`, `hostname`, `ip`, `scheme`, `port`, `path`, `scope`, and `initial_asset` with full backward compatibility.
- **Syntactic & Deterministic Validation:** Syntactic pre-validation in `validator.py`, classification in `classifier.py`, and normalization in `normalizer.py`.

### 2. Scanner Target Resolution & Applicability Matrix
- **Applicability Pre-Checks:** Enforced strict target applicability check before scanner execution.
- **IP Entry Domain Context Evaluation:** For IP targets, domain-dependent scanners (such as Email Security) evaluate derived domain assets (from PTR reverse DNS or TLS SAN certificates). If no domain is derived, Email Security evaluates to `NOT_APPLICABLE`/`UNKNOWN` without fabricating domain data.
- **Preserved SNI & Host Header Behavior:** HTTP and TLS scanners preserve SNI and Host header behavior when hostnames are derived for IP targets.

### 3. Asset Deduplication & Bounded Discovery Queue
- **Discovery Sources Tracking:** Updated `AssetManager.get_or_create_asset` to accumulate all discovery tools in the `sources` list within asset metadata (e.g. `sources: ["dns_scan", "tls_scan", "http_scan", "js_scan"]`).
- **Queue Limits:** Enforced upper bounds on discovery queue depth and asset count (`MAX_ASSETS = 100`) to prevent infinite discovery loops.

---

## Verification Artifacts

- Technical Verification Matrix updated in [`docs/Verification.md`](file:///c:/Users/roria/Downloads/Backend260826/attack-surface-engine/docs/Verification.md).
- Total Test Suite: **176 PASSED** (0 failures, 0 warnings).
