# Architecture.md

# Attack Surface Engineering Platform
## Backend Architecture and Technical Blueprint

**Document Version:** 1.0  
**Project Scope:** Backend Only  
**Architecture Type:** Modular Monolith  
**Primary Language:** Python  
**Primary Goal:** Build a modular, evidence-based direct target scanning engine.

---

# 1. PURPOSE OF THIS DOCUMENT

This document defines the technical architecture of the Attack Surface Engineering Platform.

It explains:

- How user input reaches the backend
- How the target is validated
- How the target type is identified
- How scans are selected
- How scan tools communicate with their intended receivers
- How responses are processed
- How results are validated
- How newly discovered assets are handled
- How all scan tools communicate with the central system
- Which technologies should be used
- How the project files and folders should be organized

The system is currently backend-only.

The architecture must support:

- Domain scanning
- IP scanning
- Individual scan execution
- Multiple selected scans
- Full applicable scan execution
- Independent scan tools
- Evidence-based results
- Asset discovery
- Asset correlation
- Accurate error reporting
- Future expansion

---

# 2. HIGH-LEVEL SYSTEM ARCHITECTURE

The complete system should work like this:

```text
                         USER / FRONTEND
                                │
                                │ Target + Scan Selection
                                ▼
                    ┌───────────────────────┐
                    │       API LAYER       │
                    │                       │
                    │ Receive Scan Request  │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   INPUT VALIDATOR     │
                    │                       │
                    │ Is input valid?       │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │  TARGET NORMALIZER    │
                    │                       │
                    │ Domain / IPv4 / IPv6  │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │    SCOPE CHECKER      │
                    │                       │
                    │ Is target allowed?    │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │    SCAN ORCHESTRATOR  │
                    │                       │
                    │ Selects scan tools    │
                    └───────────┬───────────┘
                                │
              ┌─────────────────┼──────────────────┐
              │                 │                  │
              ▼                 ▼                  ▼
        INDIVIDUAL         SELECTED            FULL
          SCAN              SCANS               SCAN
              │                 │                  │
              └─────────────────┼──────────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │     SCAN MANAGER      │
                    │                       │
                    │ Runs applicable tools │
                    └───────────┬───────────┘
                                │
        ┌───────────────┬───────┼────────┬───────────────┐
        │               │       │        │               │
        ▼               ▼       ▼        ▼               ▼
      DNS            PORT     HTTP      TLS           EMAIL
      SCAN           SCAN     SCAN      SCAN           SCAN
        │               │       │        │               │
        ▼               ▼       ▼        ▼               ▼
    DNS SERVER      TARGET    WEB      TLS            DNS
                    NETWORK   SERVER   SERVER         SERVER
        │               │       │        │               │
        └───────────────┴───────┼────────┴───────────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │   RESPONSE PROCESSOR  │
                    │                       │
                    │ Parse real responses  │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │    RESULT VALIDATOR   │
                    │                       │
                    │ Valid? Accurate?      │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │  ASSET PROCESSOR      │
                    │                       │
                    │ Normalize + Deduplicate
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │  ASSET CORRELATION    │
                    │                       │
                    │ Build relationships   │
                    └───────────┬───────────┘
                                │
                                ▼
                    ┌───────────────────────┐
                    │ NEW ASSET DISCOVERED? │
                    └───────────┬───────────┘
                                │
                     ┌──────────┴──────────┐
                     │                     │
                    YES                    NO
                     │                     │
                     ▼                     ▼
              SCOPE VALIDATION        FINAL RESULTS
                     │                     │
                     ▼                     ▼
              ADD TO SCAN QUEUE       API RESPONSE
                     │                     │
                     └───────► REPEAT ◄───┘
3. CORE ARCHITECTURE PRINCIPLE

The project must use a:

MODULAR MONOLITH

This means:

One backend application
One main codebase
Clear internal modules
Each scanner is independent
No unnecessary microservices
No unnecessary distributed infrastructure

The system should NOT start with:

DNS Microservice
Port Scan Microservice
HTTP Microservice
TLS Microservice
Database Microservice
Queue Microservice

This would create unnecessary complexity.

Instead:

ONE BACKEND
│
├── API
├── Core
├── Scan Orchestrator
├── Individual Scan Modules
├── Asset Management
├── Validation
├── Storage
└── Tests

If the project grows significantly later, individual modules can be separated into services.

4. RECOMMENDED TECHNOLOGY STACK
4.1 Programming Language
Python 3.12+

Python is the primary language for the entire backend.

Reasons:

Excellent networking support
Strong asynchronous capabilities
Good DNS libraries
Good HTTP support
Built-in TLS and socket capabilities
Good parsing libraries
Fast development
Easy testing
Strong cybersecurity tooling ecosystem

Do not use multiple backend languages unless there is a real technical reason.

5. BACKEND FRAMEWORK

Recommended:

FastAPI

FastAPI will handle:

REST API endpoints
Request validation
Response serialization
Async operations
API documentation
Dependency injection

Basic flow:

FRONTEND
    │
    │ POST /scans
    ▼
FASTAPI
    │
    ▼
SCAN SERVICE
    │
    ▼
SCAN ORCHESTRATOR
6. ASYNCHRONOUS EXECUTION

Many operations involve waiting for network responses.

Examples:

DNS query
HTTP request
TLS handshake
Port connection
Web crawling

Therefore, the system should use:

async / await

where appropriate.

Recommended primary HTTP client:

httpx

The architecture should avoid blocking the entire application while waiting for one network request.

Example:

DNS REQUEST ────────────────┐
HTTP REQUEST ───────────────┤
TLS REQUEST ────────────────┤
                            ▼
                    ASYNC EVENT LOOP
                            │
                            ▼
                      COLLECT RESULTS

Important:

Do not automatically run unlimited scans in parallel.

The system must use:

Concurrency limits
Timeouts
Connection limits
Rate controls
7. DATABASE

Recommended initial database:

PostgreSQL

The database should store:

Scan records
Scan status
Target information
Discovered assets
Asset relationships
Tool results
Errors
Evidence
Timestamps

Basic structure:

SCAN
 │
 ├── TARGET
 │
 ├── SCAN RESULTS
 │
 ├── DISCOVERED ASSETS
 │
 └── ERRORS
8. CACHE AND TEMPORARY STATE

Recommended:

Redis

Redis may be used for:

Temporary scan state
Background task coordination
Rate limiting
Temporary queues
Caching selected data

Redis should not replace the main database.

Basic rule:

PostgreSQL = Persistent Data

Redis = Temporary / Fast Data
9. BACKGROUND SCAN EXECUTION

Some scans may take longer than a normal HTTP request.

The API should not be responsible for performing all scan operations directly.

The recommended flow is:

USER
  │
  ▼
POST /scans
  │
  ▼
CREATE SCAN
  │
  ▼
RETURN scan_id
  │
  ▼
BACKGROUND SCAN EXECUTION
  │
  ▼
USER CHECKS STATUS

Example:

POST /api/v1/scans

Response:

{
    "scan_id": "abc123",
    "status": "queued"
}

Then:

GET /api/v1/scans/abc123

Possible response:

{
    "scan_id": "abc123",
    "status": "running",
    "progress": 45
}

Later:

{
    "scan_id": "abc123",
    "status": "completed"
}

The exact task execution technology can initially remain simple.

Do not introduce a heavy distributed task system unless required.

10. USER INPUT FLOW

The backend receives:

TARGET
+
SCAN MODE
+
SELECTED SCANS
+
SCAN CONFIGURATION

Example:

{
  "target": "example.com",
  "mode": "full",
  "scans": [],
  "configuration": {}
}

Another example:

{
  "target": "example.com",
  "mode": "selected",
  "scans": [
    "dns",
    "http",
    "tls"
  ]
}

Individual scan:

{
  "target": "example.com",
  "mode": "individual",
  "scans": [
    "dns"
  ]
}
11. TARGET VALIDATION

The first backend component must validate the target.

Possible target types:

DOMAIN
HOSTNAME
IPv4
IPv6

Input flow:

USER INPUT
     │
     ▼
INPUT VALIDATOR
     │
     ├── Valid Domain?
     │
     ├── Valid Hostname?
     │
     ├── Valid IPv4?
     │
     └── Valid IPv6?
             │
             ▼
        TARGET TYPE

Invalid targets must immediately return an error.

Example:

{
  "status": "failed",
  "error_type": "invalid_target",
  "message": "The provided target is not a valid domain or IP address."
}
12. TARGET NORMALIZATION

Before scanning, the target must be normalized.

Examples:

Example.COM
EXAMPLE.com
example.com.

Normalized:

example.com

URLs should be separated into components.

Example:

https://Example.com:443/test

Possible normalized structure:

scheme: https
hostname: example.com
port: 443
path: /test

The original value should still be preserved.

original_target
normalized_target
target_type
13. SCOPE CHECKER

Before active scanning, the architecture should include a scope validation layer.

Flow:

NORMALIZED TARGET
        │
        ▼
    SCOPE CHECK
        │
   ┌────┴────┐
   │         │
ALLOWED    NOT ALLOWED
   │         │
   ▼         ▼
SCAN      REJECT

The same check must apply to newly discovered assets before additional active scanning.

Example:

example.com
      │
      ▼
DNS DISCOVERS:
api.example.com
      │
      ▼
SCOPE CHECK
      │
      ├── Allowed → Can Scan
      │
      └── Not Allowed → Store Discovery Only
14. SCAN ORCHESTRATOR

The Scan Orchestrator is the brain of the scanning workflow.

It does not perform DNS, HTTP, TLS, or port scanning itself.

Instead, it controls the scan modules.

Responsibilities:

Determine target type
Determine scan mode
Select compatible tools
Manage dependencies
Start tools
Track tool status
Collect results
Process discovered assets
Prevent repeated work
Detect when scanning is complete

Architecture:

                   SCAN REQUEST
                        │
                        ▼
                SCAN ORCHESTRATOR
                        │
        ┌───────────────┼────────────────┐
        │               │                │
        ▼               ▼                ▼
  SCAN SELECTION    DEPENDENCY       EXECUTION
                    MANAGEMENT       CONTROL
        │               │                │
        └───────────────┼────────────────┘
                        │
                        ▼
                   SCAN TOOLS
15. SCAN DEPENDENCY MODEL

Some scans can run immediately.

Example:

DOMAIN
 │
 ├── DNS Scan
 ├── Email Security Scan
 ├── HTTP Scan
 └── TLS Scan

Some scans require previous information.

Example:

DNS Scan
    │
    ▼
IP ADDRESS
    │
    ▼
PORT DISCOVERY
    │
    ▼
OPEN PORT
    │
    ▼
SERVICE IDENTIFICATION

Another example:

HTTP Scan
    │
    ├── Technology Detection
    │
    ├── Endpoint Discovery
    │
    └── JavaScript Discovery

The orchestrator must understand these dependencies.

16. FULL SCAN EXECUTION FLOW

For a domain:

DOMAIN
   │
   ▼
TARGET NORMALIZATION
   │
   ▼
DNS SCAN
   │
   ├──────────────────────┐
   │                      │
   ▼                      ▼
IP ADDRESSES         DNS RECORDS
   │                      │
   ▼                      ▼
PORT DISCOVERY       EMAIL SECURITY
   │
   ▼
OPEN PORTS
   │
   ▼
SERVICE IDENTIFICATION
   │
   ├──────────────┐
   │              │
   ▼              ▼
HTTP SERVICE    TLS SERVICE
   │              │
   ▼              ▼
HTTP SCAN       TLS SCAN
   │              │
   ▼              ▼
WEB DATA       CERTIFICATE DATA
   │              │
   ├───────┬──────┘
   │       │
   ▼       ▼
TECH       CLOUD/CDN
DETECTION  DETECTION
   │
   ├───────────────┐
   │               │
   ▼               ▼
ENDPOINT        JAVASCRIPT
DISCOVERY       DISCOVERY
   │               │
   └───────┬───────┘
           │
           ▼
     NEW ASSET FOUND
           │
           ▼
      SCOPE CHECK
           │
           ▼
      ADD TO QUEUE
17. SCAN TOOL ARCHITECTURE

Every tool must follow the same general internal architecture.

SCAN TOOL
    │
    ├── Input Model
    │
    ├── Request Builder
    │
    ├── Transport / Connection
    │
    ├── Response Receiver
    │
    ├── Response Parser
    │
    ├── Result Extractor
    │
    ├── Validator
    │
    └── Output Model

The exact implementation may differ between tools.

For example:

DNS:

INPUT
  ↓
BUILD DNS QUERY
  ↓
SEND TO DNS SERVER
  ↓
RECEIVE DNS RESPONSE
  ↓
PARSE RECORDS
  ↓
VALIDATE RECORD FORMAT
  ↓
RETURN RESULTS

HTTP:

INPUT
  ↓
BUILD HTTP REQUEST
  ↓
SEND TO WEB SERVER
  ↓
RECEIVE HTTP RESPONSE
  ↓
PARSE HEADERS + BODY
  ↓
EXTRACT INFORMATION
  ↓
VALIDATE
  ↓
RETURN RESULTS

TLS:

HOST + PORT
  ↓
CREATE TLS CONNECTION
  ↓
TLS HANDSHAKE
  ↓
TARGET TLS SERVER
  ↓
RECEIVE CERTIFICATE
  ↓
PARSE CERTIFICATE
  ↓
VALIDATE
  ↓
RETURN RESULTS
18. DIRECT SCAN MODULES

The initial architecture includes these scan modules:

1. DNS Scan
2. Port Discovery
3. Service Identification
4. HTTP/HTTPS Scan
5. Technology Detection
6. Web Endpoint Discovery
7. JavaScript Discovery
8. Live TLS Scan
9. Email Security Scan
10. Basic Cloud/CDN Detection

Each module must be independent.

No scan module should directly depend on another module's internal code.

Modules communicate through:

INPUT MODELS
OUTPUT MODELS
ASSET MODELS
EVENTS / ORCHESTRATOR
19. ASSET PIPELINE

All discovered information should pass through a central asset pipeline.

RAW DISCOVERY
      │
      ▼
FORMAT VALIDATION
      │
      ▼
NORMALIZATION
      │
      ▼
DEDUPLICATION
      │
      ▼
SCOPE VALIDATION
      │
      ▼
ASSET CREATION
      │
      ▼
RELATIONSHIP CREATION
      │
      ▼
OPTIONAL NEW SCAN QUEUE

Example:

DNS Scan
   │
   ▼
192.0.2.10
   │
   ▼
Validate IP
   │
   ▼
Normalize
   │
   ▼
Already Exists?
   │
   ├── Yes → Update Existing Asset
   │
   └── No → Create New Asset
                    │
                    ▼
               Create Relationship

example.com
     │
     └── resolves_to → 192.0.2.10
20. ASSET DATA MODEL

Every asset should contain at least:

asset_id
asset_type
original_value
normalized_value
status
first_seen
last_seen
source_tool

Example:

{
  "asset_id": "asset_123",
  "asset_type": "ip_address",
  "original_value": "192.0.2.10",
  "normalized_value": "192.0.2.10",
  "status": "confirmed",
  "source_tool": "dns_scan"
}
21. RELATIONSHIP DATA MODEL

Assets should be connected through relationships.

Example:

{
  "source_asset": "example.com",
  "relationship": "resolves_to",
  "target_asset": "192.0.2.10",
  "source_tool": "dns_scan"
}

Architecture:

ASSET A
   │
   │ relationship
   ▼
ASSET B

Examples:

DOMAIN
   │ resolves_to
   ▼
IP ADDRESS

IP ADDRESS
   │ exposes
   ▼
PORT

PORT
   │ provides
   ▼
SERVICE

SERVICE
   │ serves
   ▼
URL

URL
   │ contains
   ▼
ENDPOINT
22. RESULT VALIDATION ARCHITECTURE

Every scan result must be validated before being marked as confirmed.

RAW RESPONSE
      │
      ▼
RESPONSE PARSER
      │
      ▼
EXTRACTED VALUE
      │
      ▼
FORMAT VALIDATION
      │
      ▼
EVIDENCE CHECK
      │
      ▼
RESULT STATUS

Possible statuses:

confirmed
detected
inferred
not_detected
unknown
failed
not_tested

The system must not use:

success = information is correct

A successful request only means the request completed.

The information still needs validation.

23. EVIDENCE ARCHITECTURE

Every important result should preserve evidence.

General structure:

RESULT
  │
  ├── VALUE
  │
  ├── SOURCE TOOL
  │
  ├── DISCOVERY METHOD
  │
  ├── RAW EVIDENCE
  │
  ├── VALIDATION METHOD
  │
  └── CONFIDENCE

Example:

{
  "technology": "nginx",
  "status": "detected",
  "evidence": {
    "type": "http_header",
    "value": "server: nginx"
  },
  "confidence": "high"
}
24. ERROR HANDLING ARCHITECTURE

Every scan module must return structured errors.

Architecture:

REQUEST
   │
   ▼
TRY OPERATION
   │
   ├── SUCCESS
   │      │
   │      ▼
   │   PARSE RESULT
   │
   └── FAILURE
          │
          ▼
      CLASSIFY ERROR
          │
          ├── timeout
          ├── connection_error
          ├── dns_error
          ├── tls_error
          ├── invalid_response
          ├── parser_error
          └── internal_error

The system must never replace an error with fake data.

25. API ARCHITECTURE

Initial API structure:

/api
│
└── /v1
    │
    ├── /scans
    │
    ├── /scans/{scan_id}
    │
    ├── /scans/{scan_id}/results
    │
    └── /health

Main endpoints:

POST   /api/v1/scans
GET    /api/v1/scans/{scan_id}
GET    /api/v1/scans/{scan_id}/results
GET    /api/v1/health

Future endpoints can be added later.

Do not create unnecessary API endpoints before they are needed.

26. SCAN STATUS MODEL

A scan should have a clear lifecycle.

created
   │
   ▼
queued
   │
   ▼
running
   │
   ├── partial_failure
   │
   ├── failed
   │
   └── completed

Example:

SCAN
 │
 ├── DNS → completed
 │
 ├── HTTP → completed
 │
 ├── TLS → failed
 │
 └── Email → completed

Overall result:

partial_failure

One failed tool should not automatically destroy all successful results.

27. PROJECT FILE AND FOLDER STRUCTURE

The recommended project structure is:

attack-surface-engine/
│
├── app/
│   │
│   ├── main.py
│   │
│   ├── api/
│   │   │
│   │   ├── router.py
│   │   │
│   │   ├── dependencies.py
│   │   │
│   │   └── routes/
│   │       │
│   │       ├── scans.py
│   │       └── health.py
│   │
│   ├── core/
│   │   │
│   │   ├── config.py
│   │   ├── logging.py
│   │   ├── constants.py
│   │   └── exceptions.py
│   │
│   ├── models/
│   │   │
│   │   ├── scan.py
│   │   ├── asset.py
│   │   ├── relationship.py
│   │   ├── evidence.py
│   │   └── results.py
│   │
│   ├── schemas/
│   │   │
│   │   ├── scan_request.py
│   │   ├── scan_response.py
│   │   ├── asset.py
│   │   └── common.py
│   │
│   ├── services/
│   │   │
│   │   ├── scan_service.py
│   │   │
│   │   ├── target/
│   │   │   ├── validator.py
│   │   │   ├── normalizer.py
│   │   │   ├── classifier.py
│   │   │   └── scope_checker.py
│   │   │
│   │   ├── assets/
│   │   │   ├── asset_manager.py
│   │   │   ├── asset_validator.py
│   │   │   ├── normalizer.py
│   │   │   ├── deduplicator.py
│   │   │   └── relationship_manager.py
│   │   │
│   │   └── results/
│   │       ├── collector.py
│   │       ├── validator.py
│   │       └── aggregator.py
│   │
│   ├── orchestrator/
│   │   │
│   │   ├── scan_orchestrator.py
│   │   ├── scan_selector.py
│   │   ├── dependency_manager.py
│   │   ├── execution_manager.py
│   │   └── asset_queue.py
│   │
│   ├── scanners/
│   │   │
│   │   ├── base/
│   │   │   ├── base_scanner.py
│   │   │   ├── models.py
│   │   │   └── exceptions.py
│   │   │
│   │   ├── dns/
│   │   │   ├── scanner.py
│   │   │   ├── query.py
│   │   │   ├── parser.py
│   │   │   ├── validator.py
│   │   │   ├── models.py
│   │   │   └── tests/
│   │   │
│   │   ├── port/
│   │   │   ├── scanner.py
│   │   │   ├── connector.py
│   │   │   ├── response_analyzer.py
│   │   │   ├── validator.py
│   │   │   ├── models.py
│   │   │   └── tests/
│   │   │
│   │   ├── service/
│   │   │   ├── scanner.py
│   │   │   ├── probes.py
│   │   │   ├── fingerprints.py
│   │   │   ├── parser.py
│   │   │   ├── validator.py
│   │   │   ├── models.py
│   │   │   └── tests/
│   │   │
│   │   ├── http/
│   │   │   ├── scanner.py
│   │   │   ├── client.py
│   │   │   ├── parser.py
│   │   │   ├── redirects.py
│   │   │   ├── validator.py
│   │   │   ├── models.py
│   │   │   └── tests/
│   │   │
│   │   ├── technology/
│   │   │   ├── scanner.py
│   │   │   ├── rules.py
│   │   │   ├── fingerprints.py
│   │   │   ├── detector.py
│   │   │   ├── validator.py
│   │   │   ├── models.py
│   │   │   └── tests/
│   │   │
│   │   ├── endpoint/
│   │   │   ├── scanner.py
│   │   │   ├── crawler.py
│   │   │   ├── extractor.py
│   │   │   ├── validator.py
│   │   │   ├── models.py
│   │   │   └── tests/
│   │   │
│   │   ├── javascript/
│   │   │   ├── scanner.py
│   │   │   ├── collector.py
│   │   │   ├── analyzer.py
│   │   │   ├── extractor.py
│   │   │   ├── validator.py
│   │   │   ├── models.py
│   │   │   └── tests/
│   │   │
│   │   ├── tls/
│   │   │   ├── scanner.py
│   │   │   ├── handshake.py
│   │   │   ├── certificate_parser.py
│   │   │   ├── validator.py
│   │   │   ├── models.py
│   │   │   └── tests/
│   │   │
│   │   ├── email/
│   │   │   ├── scanner.py
│   │   │   ├── dns_queries.py
│   │   │   ├── policy_parser.py
│   │   │   ├── validator.py
│   │   │   ├── models.py
│   │   │   └── tests/
│   │   │
│   │   └── cloud/
│   │       ├── scanner.py
│   │       ├── detector.py
│   │       ├── rules.py
│   │       ├── validator.py
│   │       ├── models.py
│   │       └── tests/
│   │
│   ├── database/
│   │   │
│   │   ├── session.py
│   │   ├── models/
│   │   └── repositories/
│   │
│   └── workers/
│       │
│       ├── scan_worker.py
│       └── task_manager.py
│
├── tests/
│   │
│   ├── integration/
│   ├── api/
│   └── fixtures/
│
├── docs/
│   │
│   ├── PRD.md
│   ├── Architecture.md
│   ├── Rules.md
│   ├── Phases.md
│   ├── Design.md
│   └── Memory.md
│
├── scripts/
│
├── requirements/
│
├── .env.example
├── pyproject.toml
├── README.md
└── docker-compose.yml
28. SCANNER FOLDER RULE

Every scanner must have its own folder.

Example:

scanners/
│
├── dns/
├── port/
├── service/
├── http/
├── technology/
├── endpoint/
├── javascript/
├── tls/
├── email/
└── cloud/

Each scanner should contain only the logic related to that scanner.

Example:

dns/
│
├── scanner.py
├── query.py
├── parser.py
├── validator.py
├── models.py
└── tests/

This makes debugging easier.

If the DNS scanner has a problem:

scanners/dns/

is the primary location to investigate.

29. BASE SCANNER INTERFACE

All scan tools should follow a common scanner interface.

Conceptually:

BaseScanner
    │
    ├── validate_input()
    │
    ├── execute()
    │
    ├── parse_response()
    │
    ├── validate_result()
    │
    └── build_result()

Each scanner implements its own internal logic.

Example:

DNSScanner
PortScanner
HTTPScanner
TLSScanner

The orchestrator should communicate with all scanners through a predictable interface.

30. REQUEST FLOW INSIDE A SCANNER

Every scanner must clearly follow:

INPUT
  │
  ▼
VALIDATE INPUT
  │
  ▼
BUILD REQUEST
  │
  ▼
CONNECT TO INTENDED RECEIVER
  │
  ▼
SEND REQUEST
  │
  ▼
WAIT FOR RESPONSE
  │
  ├── RESPONSE RECEIVED
  │        │
  │        ▼
  │      PARSE
  │        │
  │        ▼
  │     VALIDATE
  │        │
  │        ▼
  │   STRUCTURED RESULT
  │
  └── FAILURE
           │
           ▼
      STRUCTURED ERROR

Every scanner must document its intended receiver.

Examples:

DNS Scan
Receiver: DNS Server

Port Discovery
Receiver: Target Network Stack

HTTP Scan
Receiver: Target Web Server

TLS Scan
Receiver: Target TLS Server

JavaScript Discovery
Receiver: Target Web Server / CDN
31. RESULT FLOW

All scanner results should follow this pipeline:

SCAN RESULT
    │
    ▼
RESULT COLLECTOR
    │
    ▼
RESULT VALIDATOR
    │
    ▼
ASSET EXTRACTOR
    │
    ▼
ASSET NORMALIZER
    │
    ▼
DEDUPLICATOR
    │
    ▼
RELATIONSHIP MANAGER
    │
    ▼
DATABASE
    │
    ▼
FINAL RESULT AGGREGATOR
32. DEDUPLICATION

The same asset may be discovered by multiple tools.

Example:

DNS Scan → api.example.com

TLS Certificate → api.example.com

JavaScript → api.example.com

The system should not create:

3 separate assets

Instead:

ONE ASSET

api.example.com

Sources:
- DNS Scan
- TLS Scan
- JavaScript Discovery

This increases confidence and preserves evidence.

33. SCAN QUEUE ARCHITECTURE

Newly discovered assets may need additional scanning.

Example:

DNS
 │
 ▼
192.0.2.10
 │
 ▼
ASSET QUEUE
 │
 ▼
PORT DISCOVERY

The queue must prevent:

INFINITE LOOP

Example:

Asset A discovers Asset B
Asset B discovers Asset A
Asset A scans again
Asset B scans again

The system must track:

asset_id
scan_type
scan_status

Example:

asset_123 + dns_scan = completed

Do not repeat the same scan unnecessarily.

34. LOGGING ARCHITECTURE

The backend must use structured logging.

Every important operation should include:

scan_id
tool_name
asset_id
target
event
status
timestamp

Example:

scan_id=123
tool=dns
target=example.com
event=dns_query_started
status=running

Example:

scan_id=123
tool=dns
target=example.com
event=dns_query_completed
status=success

Do not log unnecessary sensitive response data.

35. TEST ARCHITECTURE

Every scanner must be tested independently.

Testing structure:

tests/
│
├── unit/
│
├── integration/
│
├── api/
│
└── fixtures/

Each scanner also has local tests:

scanners/dns/tests/
scanners/port/tests/
scanners/http/tests/

Each scanner must test:

1. Valid input
2. Invalid input
3. Valid response
4. Invalid response
5. Timeout
6. Connection failure
7. Parser failure
8. Duplicate result
9. No result
10. Structured output
36. DEVELOPMENT ORDER

The system must be built one tool at a time.

Recommended order:

STEP 1
Core Backend Foundation

↓

STEP 2
Target Validation + Normalization

↓

STEP 3
Scan Data Models

↓

STEP 4
DNS Scanner

↓

TEST DNS COMPLETELY

↓

STEP 5
Port Discovery

↓

TEST PORT DISCOVERY COMPLETELY

↓

STEP 6
Service Identification

↓

TEST COMPLETELY

↓

STEP 7
HTTP/HTTPS Scanner

↓

TEST COMPLETELY

↓

STEP 8
Technology Detection

↓

TEST COMPLETELY

↓

STEP 9
Web Endpoint Discovery

↓

TEST COMPLETELY

↓

STEP 10
JavaScript Discovery

↓

TEST COMPLETELY

↓

STEP 11
Live TLS Scanner

↓

TEST COMPLETELY

↓

STEP 12
Email Security Scanner

↓

TEST COMPLETELY

↓

STEP 13
Cloud/CDN Detection

↓

TEST COMPLETELY

↓

STEP 14
Asset Correlation

↓

STEP 15
Full Scan Orchestration

Do not build all scanners at the same time.

37. MEMORY.md INTEGRATION

After completing each development step, update:

docs/Memory.md

Example:

# Current Status

Current Phase:
Phase 2

Current Component:
DNS Scanner

Status:
Completed

Tests:
Passed

Known Issues:
None

Next Component:
Port Discovery

Memory.md is the development state tracker.

It must always reflect the real current state of the project.

38. IMPORTANT ARCHITECTURE RULES

The architecture must follow these rules:

RULE 1
One scanner = one independent module.

RULE 2
Do not mix all scanner logic in one file.

RULE 3
Every discovered result must have a source.

RULE 4
Every important result should preserve evidence.

RULE 5
Failed requests must not generate fake results.

RULE 6
Unknown is better than an incorrect answer.

RULE 7
Do not guess technologies, services, or assets.

RULE 8
New assets must be validated before active scanning.

RULE 9
Repeated scans must be controlled.

RULE 10
One scanner failing must not automatically fail the entire scan.

RULE 11
Build one scanner, test it, then move to the next.

RULE 12
Update Memory.md after every completed development milestone.

RULE 13
Keep scanner communication through clear input/output models.

RULE 14
Do not introduce unnecessary microservices.

RULE 15
Start simple and modular.
39. FINAL ARCHITECTURAL FLOW

The complete backend architecture is:

USER / FRONTEND
        │
        ▼
    FASTAPI API
        │
        ▼
  INPUT VALIDATION
        │
        ▼
TARGET NORMALIZATION
        │
        ▼
    SCOPE CHECK
        │
        ▼
 CREATE SCAN RECORD
        │
        ▼
  SCAN ORCHESTRATOR
        │
        ▼
 DETERMINE SCAN MODE
        │
        ├── Individual
        │
        ├── Selected
        │
        └── Full Applicable
                │
                ▼
          SCAN MANAGER
                │
                ▼
        ┌──── SCANNERS ────┐
        │                  │
        ├── DNS            │
        ├── PORT           │
        ├── SERVICE        │
        ├── HTTP           │
        ├── TECHNOLOGY     │
        ├── ENDPOINT       │
        ├── JAVASCRIPT     │
        ├── TLS            │
        ├── EMAIL          │
        └── CLOUD/CDN      │
                           │
                           ▼
                   DIRECT REQUEST
                           │
                           ▼
                   INTENDED RECEIVER
                           │
                           ▼
                     REAL RESPONSE
                           │
                           ▼
                    RESPONSE PARSER
                           │
                           ▼
                    RESULT VALIDATOR
                           │
                           ▼
                    ASSET PROCESSOR
                           │
                           ▼
                    DEDUPLICATION
                           │
                           ▼
                 RELATIONSHIP MANAGER
                           │
                           ▼
                  NEW ASSET DISCOVERED?
                           │
                    ┌──────┴──────┐
                    │             │
                   YES            NO
                    │             │
                    ▼             ▼
                SCOPE CHECK    AGGREGATE
                    │           RESULTS
                    ▼             │
                SCAN QUEUE        ▼
                    │         API RESPONSE
                    └───────┐
                            │
                            ▼
                        NEXT SCAN
40. FINAL ARCHITECTURE DEFINITION

The system architecture is a modular Python backend built around a central Scan Orchestrator.

Each scanning capability is implemented as an independent module.

The overall system is responsible for:

INPUT
  ↓
VALIDATE
  ↓
NORMALIZE
  ↓
CHECK SCOPE
  ↓
SELECT SCANS
  ↓
EXECUTE SCANNERS
  ↓
SEND DIRECT REQUESTS
  ↓
RECEIVE REAL RESPONSES
  ↓
PARSE RESPONSES
  ↓
VALIDATE RESULTS
  ↓
STORE EVIDENCE
  ↓
CREATE ASSETS
  ↓
REMOVE DUPLICATES
  ↓
BUILD RELATIONSHIPS
  ↓
PROCESS NEW ASSETS
  ↓
AGGREGATE RESULTS
  ↓
RETURN FINAL ATTACK SURFACE DATA

The architecture must remain:

Modular
Testable
Traceable
Evidence-based
Accurate
Extensible
Easy to debug
Easy for an AI coding assistant to understand
Simple enough to build step by step