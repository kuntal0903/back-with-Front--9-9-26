# Memory.md
# Attack Surface Engineering Platform — Development State Tracker

**Last Updated:** 2026-09-03
**Document Purpose:** Persistent project state. Read this before starting any development session.

---

## Current Status

**GIT REPOSITORY ORGANIZATION, SEPARATE FRONTEND/BACKEND VERCEL DEPLOYMENT & E2E SCANNER VERIFICATION**
**Status:** COMPLETED & VERIFIED ✅
**Backend Tests:** 176/176 passed (`pytest`, Python 3.12+, 0 failures)
**Frontend Build:** PASSED (`Vite 6` SPA, `dist/index.html` compiled cleanly)
**Git Repository:** [`https://github.com/kuntal0903/back-with-Front--9-9-26.git`](https://github.com/kuntal0903/back-with-Front--9-9-26.git)
**Frontend Deployment:** [`https://frontend-one-mu-61.vercel.app`](https://frontend-one-mu-61.vercel.app)
**Backend Deployment:** [`https://backend-nine-psi-jfylpksuh6.vercel.app`](https://backend-nine-psi-jfylpksuh6.vercel.app)

---

## Summary of Completed Deployment Improvements

### 1. Repository Layout & Git Setup
- Clean root structure with `backend/`, `frontend/`, and root markdown documentation (`PRD.md`, `Architecture.md`, `Rules.md`, `Phases.md`, `Design.md`, `Memory.md`, `Verification.md`).
- Redundant directories and leftover files removed.
- Remote repository updated and synced to `https://github.com/kuntal0903/back-with-Front--9-9-26.git` on `main` branch.

### 2. Backend Engine & Vercel Integration
- `FastAPI` configured with dynamic `CORSMiddleware` using `settings.allowed_origins`.
- Root `/health` probe and `/api/v1/health` returning HTTP 200 OK with system metrics.
- Vercel Serverless Function entry point `backend/api/index.py` and `backend/vercel.json` deployed to Vercel production.
- Added optional `sync=True` parameter to `POST /api/v1/scans` for synchronous execution on serverless platforms.

### 3. Frontend UI & REST API Integration
- `frontend/src/api/scanApi.js` connected to environment-configured `VITE_API_URL`.
- `frontend/.env.production` set to `https://backend-nine-psi-jfylpksuh6.vercel.app`.
- Deployed separately on Vercel (`https://frontend-one-mu-61.vercel.app`) with SPA rewrite rules in `frontend/vercel.json`.

---

## E2E Network & Scanner Verification Matrix

| Target / Operation | Endpoint | HTTP Status | Response / Evidence | Verification Status |
| :--- | :--- | :--- | :--- | :--- |
| **Backend Health** | `GET /health` | 200 OK | `{"status":"healthy","version":"0.1.0"}` | VERIFIED |
| **API Health** | `GET /api/v1/health` | 200 OK | `{"status":"healthy","db_status":"healthy"}` | VERIFIED |
| **CORS Preflight** | `OPTIONS /api/v1/scans` | 200 OK | `Access-Control-Allow-Origin: https://frontend-one-mu-61.vercel.app` | VERIFIED |
| **Real Scan Execution**| `POST /api/v1/scans?sync=true` | 201 Created | `{"scan_id":"...","status":"completed"}` | VERIFIED |
| **Scan Results** | `GET /api/v1/scans/{id}/results` | 200 OK | Real DNS, HTTP, TLS cert, & Email evidence | VERIFIED |
| **Invalid Target Error**| `POST /api/v1/scans` | 400 Bad Request| Structured error `{"status":"failed","error_type":"invalid_target"}` | VERIFIED |

---

## Scanner Production Capabilities Matrix

| Scanner Tool | Local | Vercel Serverless | Execution Evidence / Technical Limitation |
| :--- | :--- | :--- | :--- |
| **DNS Scanner** | VERIFIED | VERIFIED | Resolves A, AAAA, MX, NS, TXT, CNAME via system DNS resolver |
| **Port Scanner** | VERIFIED | LIMITED | Lambda outbound firewall limits raw socket TCP SYN/connect scans on high ports |
| **Service Scanner** | VERIFIED | LIMITED | TCP greeting reads limited to standard open outbound ports (80, 443) |
| **HTTP Scanner** | VERIFIED | VERIFIED | Async GET/HEAD via httpx, extracts titles, headers, status codes |
| **Technology Scanner** | VERIFIED | VERIFIED | Regex fingerprinting on HTTP headers and DOM assets |
| **Endpoint Scanner** | VERIFIED | VERIFIED | Parses HTML hrefs, forms, robots.txt, sitemap.xml |
| **JavaScript Scanner** | VERIFIED | VERIFIED | Regex static analysis on JS files for API routes & URLs |
| **TLS Scanner** | VERIFIED | VERIFIED | Performs TLS 1.3 handshake on 443, extracts DER certs & SANs |
| **Email Security** | VERIFIED | VERIFIED | Evaluates MX resolution, SPF mechanisms, DMARC policies |
| **Cloud/CDN Scanner** | VERIFIED | VERIFIED | Multi-signal correlation of CNAMEs, headers, and certificates |