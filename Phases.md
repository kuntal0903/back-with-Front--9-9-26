# Phases.md

# Attack Surface Engineering Platform
## Development Phases and Implementation Roadmap

**Document Version:** 1.0  
**Project Scope:** Backend Only  
**Primary Language:** Python 3.12+  
**Architecture:** Modular Monolith  
**Development Strategy:** Build → Test → Verify → Update Memory → Continue

---

# 1. PURPOSE OF THIS DOCUMENT

This document breaks the project into small, manageable development phases.

The AI or developer must NOT attempt to build the complete system in one step.

The project must be developed in this order:

```text
PLAN
 ↓
BUILD SMALL COMPONENT
 ↓
TEST
 ↓
VERIFY REAL OUTPUT
 ↓
FIX PROBLEMS
 ↓
RETEST
 ↓
MARK COMPLETE
 ↓
UPDATE Memory.md
 ↓
MOVE TO NEXT PHASE

The main objective is to prevent:

Building everything at once
Creating untested code
Mixing unrelated features
Losing project context
Breaking working components
Creating unnecessary complexity
Moving forward with incomplete modules
2. PHASE DEVELOPMENT RULE

A phase is NOT complete because the code was written.

A phase is complete only when:

[ ] Required functionality exists

[ ] Input validation works

[ ] Expected output is verified

[ ] Error handling works

[ ] Relevant tests exist

[ ] Tests pass

[ ] No fake production data exists

[ ] Known issues are documented

[ ] Memory.md is updated

Only after completion can development move to the next phase.

3. COMPLETE DEVELOPMENT ROADMAP
PHASE 0
Project Foundation
        ↓
PHASE 1
Core Backend + Target Processing
        ↓
PHASE 2
Core Scan Models + Scanner Framework
        ↓
PHASE 3
DNS Scanner
        ↓
PHASE 4
Port Discovery Scanner
        ↓
PHASE 5
Service Identification Scanner
        ↓
PHASE 6
HTTP/HTTPS Scanner
        ↓
PHASE 7
Technology Detection Scanner
        ↓
PHASE 8
Web Endpoint Discovery Scanner
        ↓
PHASE 9
JavaScript Discovery Scanner
        ↓
PHASE 10
TLS/Certificate Scanner
        ↓
PHASE 11
Email Security Scanner
        ↓
PHASE 12
Cloud/CDN Detection Scanner
        ↓
PHASE 13
Asset Management + Correlation
        ↓
PHASE 14
Scan Orchestrator
        ↓
PHASE 15
Full Scan Workflow
        ↓
PHASE 16
Integration Testing + Hardening
        ↓
PHASE 17
Production Readiness
PHASE 0 — PROJECT FOUNDATION
Goal

Create a clean backend project structure.

Do not build scanning functionality yet.

Build

Create:

project root
│
├── app/
├── tests/
├── docs/
├── scripts/
├── requirements/
├── pyproject.toml
├── .env.example
├── README.md
└── docker-compose.yml

Create the documentation files:

docs/
├── PRD.md
├── Architecture.md
├── Rules.md
├── Phases.md
├── Design.md
└── Memory.md
Configure

Set up:

Python 3.12+
FastAPI
Pydantic
pytest
Structured logging
Environment configuration
Basic application startup
Test

Verify:

[ ] Application starts

[ ] Dependencies install successfully

[ ] Configuration loads

[ ] Basic health endpoint works

[ ] Test framework runs
Completion Output

Example:

GET /health

{
  "status": "healthy"
}
Phase Complete When
[ ] Backend starts successfully

[ ] Folder structure exists

[ ] Basic API works

[ ] Test environment works

[ ] Memory.md updated
PHASE 1 — CORE BACKEND AND TARGET PROCESSING
Goal

Build the system that accepts and understands user targets.

The system must determine what the user entered.

Possible inputs:

example.com
api.example.com
192.0.2.10
2001:db8::1
Build

Create:

Target Validator
Target Classifier
Target Normalizer
Scope Checker
Scan Request Model
Scan Status Model
Required Flow
USER INPUT
    │
    ▼
VALIDATE
    │
    ├── Invalid
    │      │
    │      ▼
    │   ERROR
    │
    ▼
CLASSIFY
    │
    ├── DOMAIN
    ├── HOSTNAME
    ├── IPv4
    └── IPv6
    │
    ▼
NORMALIZE
    │
    ▼
STRUCTURED TARGET
Information Produced
original_target
normalized_target
target_type
validation_status
Test Cases
[ ] Valid domain

[ ] Domain with uppercase letters

[ ] Domain with trailing dot

[ ] Valid hostname

[ ] Valid IPv4

[ ] Valid IPv6

[ ] Invalid domain

[ ] Invalid IP

[ ] Empty input

[ ] Malformed input
Phase Complete When
[ ] Target validation works

[ ] Target classification works

[ ] Target normalization works

[ ] Invalid input returns structured errors

[ ] Tests pass

[ ] Memory.md updated
PHASE 2 — CORE SCAN MODELS AND SCANNER FRAMEWORK
Goal

Create the common foundation that every scanner will use.

Do not build individual scanning logic yet.

Build

Create:

Base Scanner Interface

Scan Input Model

Scan Result Model

Scan Error Model

Evidence Model

Asset Model

Scan Status Model
Common Scanner Flow

Every scanner should conceptually follow:

INPUT
  ↓
VALIDATE INPUT
  ↓
EXECUTE
  ↓
PARSE RESPONSE
  ↓
VALIDATE RESULT
  ↓
BUILD STRUCTURED OUTPUT
Example Result
{
  "tool": "dns_scan",
  "status": "completed",
  "results": [],
  "errors": [],
  "evidence": []
}
Test

Verify:

[ ] All models validate correctly

[ ] Invalid data is rejected

[ ] Scanner interface is consistent

[ ] Error model works

[ ] Result model works

[ ] Evidence model works
Phase Complete When
[ ] Common models are stable

[ ] Scanner interface is defined

[ ] Tests pass

[ ] No scanner-specific logic is mixed into core code

[ ] Memory.md updated
PHASE 3 — DNS SCANNER
Goal

Build the first real scanner.

The DNS scanner receives a domain or hostname and directly queries DNS infrastructure.

Input
example.com
Request Receiver
DNS SERVER / RESOLVER
Request Flow
DOMAIN
   │
   ▼
BUILD DNS QUERY
   │
   ▼
SEND QUERY TO DNS SERVER
   │
   ▼
DNS RESPONSE
   │
   ▼
PARSE RECORDS
   │
   ▼
VALIDATE RECORDS
   │
   ▼
STRUCTURED RESULT
Information Types

The scanner should support applicable DNS records:

A
AAAA
CNAME
MX
NS
TXT
SOA
CAA
Information Output

Possible output:

IPv4 addresses
IPv6 addresses
Canonical names
Mail servers
Name servers
TXT records
DNS authority information
Certificate authority authorization
Record TTL
Test
[ ] Valid domain

[ ] Domain without record type

[ ] NXDOMAIN

[ ] Timeout

[ ] Malformed response

[ ] Multiple records

[ ] IPv4 validation

[ ] IPv6 validation

[ ] Duplicate records

[ ] Structured errors
Phase Complete When
[ ] DNS queries work

[ ] Responses are parsed correctly

[ ] Results are validated

[ ] No fake DNS data exists

[ ] Tests pass

[ ] Realistic results reviewed

[ ] Memory.md updated
PHASE 4 — PORT DISCOVERY SCANNER
Goal

Determine which authorized target ports are reachable.

Input
IP address
or
Resolved hostname
Request Receiver
TARGET OPERATING SYSTEM / NETWORK STACK
Flow
TARGET IP
    │
    ▼
SELECT AUTHORIZED PORT RANGE
    │
    ▼
ATTEMPT CONNECTION / PROBE
    │
    ▼
TARGET RESPONSE
    │
    ├── Connection Accepted
    │
    ├── Connection Refused
    │
    ├── Timeout
    │
    └── Other Network Error
    │
    ▼
CLASSIFY RESULT
    │
    ▼
STRUCTURED PORT RESULT
Information Types

Possible results:

Port number
Protocol
Reachability state
Response status
Scan timing
Error information

Important:

Port state must not automatically be treated as service identification.

Test
[ ] Reachable port

[ ] Refused port

[ ] Timeout

[ ] Invalid IP

[ ] Invalid port

[ ] Duplicate port

[ ] Concurrency control

[ ] Timeout control
Phase Complete When
[ ] Port checks work correctly

[ ] Results are classified correctly

[ ] No service is guessed from port number

[ ] Tests pass

[ ] Memory.md updated
PHASE 5 — SERVICE IDENTIFICATION SCANNER
Goal

Identify the actual service running on a discovered reachable port.

Input
IP address
+
Port
Dependency

Normally:

Port Discovery
    ↓
Reachable Port
    ↓
Service Identification
Request Receiver
SERVICE RUNNING ON THE TARGET PORT
Flow
IP + PORT
    │
    ▼
CONNECT
    │
    ▼
PROTOCOL NEGOTIATION
    │
    ▼
SERVICE RESPONSE
    │
    ▼
FINGERPRINT / PARSE
    │
    ▼
VALIDATE
    │
    ▼
SERVICE RESULT
Information Types

Possible information:

Protocol
Service name
Service banner
Service metadata
Version information when explicitly exposed
Detection confidence
Evidence
Rules

Do not do:

Port 80
↓
Therefore HTTP

Instead:

Port 80
↓
Connect
↓
Protocol behavior
↓
Response evidence
↓
Confirmed or unknown
Phase Complete When
[ ] Service identification uses actual responses

[ ] No service is guessed only from port number

[ ] Evidence is preserved

[ ] Unknown is supported

[ ] Tests pass

[ ] Memory.md updated
PHASE 6 — HTTP/HTTPS SCANNER
Goal

Collect directly observable HTTP and HTTPS information.

Input
URL
or
Hostname
or
IP + Port when applicable
Request Receiver
TARGET WEB SERVER / APPLICATION
Flow
TARGET
   │
   ▼
BUILD HTTP REQUEST
   │
   ▼
SEND REQUEST
   │
   ▼
WEB SERVER
   │
   ▼
HTTP RESPONSE
   │
   ├── Status Code
   ├── Headers
   ├── Body
   ├── Cookies
   └── Redirect
   │
   ▼
PARSE
   │
   ▼
VALIDATE
   │
   ▼
STRUCTURED RESULT
Information Types

Possible information:

HTTP status
Response headers
Server header when present
Page title
Content type
Cookies
Redirect chain
Final URL
Response timing
Security-related headers when present
Controls
Maximum redirects
Timeout
Response size limit
Safe error handling
Phase Complete When
[ ] HTTP requests work

[ ] HTTPS works

[ ] Redirects are controlled

[ ] Headers are parsed

[ ] Response size is controlled

[ ] Errors are structured

[ ] Tests pass

[ ] Memory.md updated
PHASE 7 — TECHNOLOGY DETECTION SCANNER
Goal

Detect observable technologies using evidence-based rules.

Input
HTTP response
Headers
HTML
Scripts
Other observable metadata
Dependency

Normally:

HTTP Scanner
    ↓
HTTP Evidence
    ↓
Technology Detection
Flow
HTTP DATA
   │
   ▼
FINGERPRINT RULES
   │
   ▼
MATCH EVIDENCE
   │
   ▼
CALCULATE CONFIDENCE
   │
   ▼
TECHNOLOGY RESULT
Information Types

Possible detections:

Web server
Framework
CMS
Frontend framework
JavaScript libraries
CDN indicators
WAF indicators
Other observable technology markers
Rules

Every detection must include:

Technology
Detection method
Evidence
Confidence

Do not guess technologies.

Phase Complete When
[ ] Detection rules are explicit

[ ] Evidence is stored

[ ] Confidence is reasonable

[ ] Unknown is supported

[ ] Tests pass

[ ] Memory.md updated
PHASE 8 — WEB ENDPOINT DISCOVERY SCANNER
Goal

Discover observable web paths and endpoints.

Input
Website URL
Request Receiver
TARGET WEB SERVER / APPLICATION
Flow
START URL
    │
    ▼
FETCH PAGE
    │
    ▼
PARSE LINKS
    │
    ├── Internal URLs
    ├── Forms
    ├── Public paths
    └── Referenced resources
    │
    ▼
NORMALIZE
    │
    ▼
DEDUPLICATE
    │
    ▼
VALIDATE
    │
    ▼
QUEUE NEW IN-SCOPE URL
Information Types

Possible output:

URLs
Paths
Endpoints
Query parameters observed in links
Forms
Form methods
Referenced resources
Robots.txt references
Sitemap references when available
Controls
Maximum crawl depth
Maximum URLs
Scope restrictions
Duplicate prevention
Timeout
Response size limits
Phase Complete When
[ ] URLs are discovered correctly

[ ] Scope is respected

[ ] Duplicates are removed

[ ] Crawl limits work

[ ] Tests pass

[ ] Memory.md updated
PHASE 9 — JAVASCRIPT DISCOVERY SCANNER
Goal

Collect JavaScript resources and extract directly observable references.

Input
Website
or
JavaScript file
Request Receiver
TARGET WEB SERVER / CDN
Flow
WEB PAGE
    │
    ▼
FIND SCRIPT REFERENCES
    │
    ▼
FETCH JS FILES
    │
    ▼
STATIC ANALYSIS
    │
    ├── URLs
    ├── Paths
    ├── API references
    └── Hostnames
    │
    ▼
NORMALIZE
    │
    ▼
VALIDATE
    │
    ▼
STRUCTURED RESULT
Information Types

Possible output:

JavaScript file URL
Referenced endpoints
API paths
Hostnames
External domains
URL-like references
Configuration values that are intentionally public

Do not claim every string found in JavaScript is a real live endpoint.

Phase Complete When
[ ] JavaScript files are collected

[ ] References are extracted

[ ] Results are normalized

[ ] False certainty is avoided

[ ] Tests pass

[ ] Memory.md updated
PHASE 10 — TLS AND CERTIFICATE SCANNER
Goal

Collect directly observable TLS and certificate information.

Input
Hostname or IP
+
Port
Request Receiver
TARGET TLS SERVER
Flow
HOST + PORT
    │
    ▼
CREATE CONNECTION
    │
    ▼
START TLS HANDSHAKE
    │
    ▼
TLS SERVER RESPONSE
    │
    ▼
RECEIVE CERTIFICATE
    │
    ▼
PARSE
    │
    ├── Subject
    ├── Issuer
    ├── SAN
    ├── Validity
    └── Other certificate fields
    │
    ▼
VALIDATE
    │
    ▼
STRUCTURED RESULT
Information Types

Possible output:

Certificate subject
Certificate issuer
Subject Alternative Names
Validity start
Validity expiry
Serial information when exposed
TLS protocol information
Observable cipher information
Certificate chain information when available
Phase Complete When
[ ] TLS connection works

[ ] Certificate parsing works

[ ] SAN extraction works

[ ] TLS errors are structured

[ ] Tests pass

[ ] Memory.md updated
PHASE 11 — EMAIL SECURITY SCANNER
Goal

Collect and analyze directly observable email-related DNS security configuration.

Input
Domain
Request Receiver
DNS SERVER / RESOLVER
Flow
DOMAIN
   │
   ▼
DNS QUERIES
   │
   ├── MX
   ├── SPF
   ├── DKIM location when configured
   ├── DMARC
   └── MTA-STS related records
   │
   ▼
DNS RESPONSE
   │
   ▼
PARSE
   │
   ▼
VALIDATE
   │
   ▼
EMAIL SECURITY RESULT
Information Types

Possible output:

Mail servers
SPF presence
SPF record
DMARC presence
DMARC policy
DKIM selector results when a selector is known or otherwise available to the configured scan method
MTA-STS indicators
DNS-based email configuration

Important:

The scanner must not claim that all DKIM selectors have been discovered unless the configured discovery method actually supports that claim.

Phase Complete When
[ ] DNS records are queried correctly

[ ] Policies are parsed correctly

[ ] Missing records are handled correctly

[ ] No unsupported assumptions are made

[ ] Tests pass

[ ] Memory.md updated
PHASE 12 — CLOUD/CDN DETECTION SCANNER
Goal

Identify observable cloud, CDN, hosting, or infrastructure indicators.

Input
Domain
IP
DNS results
HTTP evidence
TLS evidence
Flow
AVAILABLE EVIDENCE
    │
    ├── DNS
    ├── CNAME
    ├── HTTP Headers
    ├── TLS
    └── Network Metadata
    │
    ▼
DETECTION RULES
    │
    ▼
MATCH EVIDENCE
    │
    ▼
CONFIDENCE
    │
    ▼
INFRASTRUCTURE RESULT
Information Types

Possible output:

CDN indicators
Cloud provider indicators
Hosting indicators
Proxy indicators
WAF indicators
Detection evidence
Confidence
Rule

Do not claim a provider based on weak assumptions.

Example:

One indirect clue
    ↓
Possible / Low confidence

Multiple strong indicators:

Multiple matching signals
    ↓
Detected / Higher confidence
Phase Complete When
[ ] Rules are explicit

[ ] Evidence is preserved

[ ] Confidence is calculated

[ ] Unknown is supported

[ ] Tests pass

[ ] Memory.md updated
PHASE 13 — ASSET MANAGEMENT AND CORRELATION
Goal

Turn separate scanner results into a connected attack-surface model.

Build

Create:

Asset Manager
Asset Normalizer
Asset Validator
Deduplicator
Relationship Manager
Evidence Aggregator
Asset Types

Initial support:

Domain
Hostname
IP Address
Port
Service
URL
Endpoint
JavaScript File
TLS Certificate
Mail Server
Technology
Infrastructure Indicator
Flow
RAW RESULT
    │
    ▼
EXTRACT ASSET
    │
    ▼
VALIDATE
    │
    ▼
NORMALIZE
    │
    ▼
CHECK DUPLICATE
    │
    ├── Existing Asset
    │       │
    │       ▼
    │   ADD NEW EVIDENCE
    │
    └── New Asset
            │
            ▼
        CREATE ASSET
            │
            ▼
    CREATE RELATIONSHIP
Example
example.com
    │
    │ resolves_to
    ▼
192.0.2.10
    │
    │ exposes
    ▼
443
    │
    │ provides
    ▼
HTTPS
    │
    │ serves
    ▼
https://example.com/
Phase Complete When
[ ] Assets are normalized

[ ] Duplicates are merged correctly

[ ] Evidence sources are preserved

[ ] Relationships work

[ ] Tests pass

[ ] Memory.md updated
PHASE 14 — SCAN ORCHESTRATOR
Goal

Build the central component that coordinates all completed scanners.

Do not build new scanners in this phase.

Use the scanners already completed.

Responsibilities
Select applicable scanners

Manage dependencies

Start scan modules

Control concurrency

Track status

Collect results

Handle partial failures

Process new assets

Prevent repeated scans
Flow
SCAN REQUEST
    │
    ▼
TARGET TYPE
    │
    ▼
SCAN MODE
    │
    ├── Individual Scan
    │
    ├── Selected Scans
    │
    └── Full Applicable Scan
            │
            ▼
    SELECT COMPATIBLE TOOLS
            │
            ▼
    CHECK DEPENDENCIES
            │
            ▼
    EXECUTE TOOLS
            │
            ▼
    COLLECT RESULTS
            │
            ▼
    PROCESS NEW ASSETS
            │
            ▼
    CHECK NEW SCAN DEPENDENCIES
            │
            ▼
    FINAL AGGREGATION
Test
[ ] Individual scan works

[ ] Selected scans work

[ ] Full scan works

[ ] Dependencies work

[ ] Independent scans can run concurrently

[ ] Failures are isolated

[ ] Duplicate scans are prevented

[ ] Status tracking works
Phase Complete When
[ ] Orchestrator controls completed scanners

[ ] No scanner logic is moved into orchestrator

[ ] Partial failures work correctly

[ ] Tests pass

[ ] Memory.md updated
PHASE 15 — FULL SCAN WORKFLOW
Goal

Connect all completed components into one complete scan pipeline.

Complete Flow
USER INPUT
    │
    ▼
API
    │
    ▼
VALIDATE TARGET
    │
    ▼
NORMALIZE TARGET
    │
    ▼
CHECK SCOPE
    │
    ▼
CREATE SCAN
    │
    ▼
SCAN ORCHESTRATOR
    │
    ▼
RUN APPLICABLE SCANNERS
    │
    ├── DNS
    ├── PORT
    ├── SERVICE
    ├── HTTP
    ├── TECHNOLOGY
    ├── ENDPOINT
    ├── JAVASCRIPT
    ├── TLS
    ├── EMAIL
    └── CLOUD/CDN
          │
          ▼
    COLLECT RESULTS
          │
          ▼
    VALIDATE RESULTS
          │
          ▼
    PROCESS ASSETS
          │
          ▼
    CORRELATE RELATIONSHIPS
          │
          ▼
    PROCESS NEW IN-SCOPE ASSETS
          │
          ▼
    AGGREGATE RESULTS
          │
          ▼
      FINAL OUTPUT
Phase Complete When
[ ] Domain full scan works

[ ] IP full scan works where applicable

[ ] Individual scan works

[ ] Selected scan works

[ ] Results are aggregated correctly

[ ] Partial failure works

[ ] Tests pass

[ ] Memory.md updated
PHASE 16 — INTEGRATION TESTING AND HARDENING
Goal

Test the entire system as one application.

Focus on finding architectural problems.

Test Areas
Target validation

Scan dependencies

Concurrency

Timeouts

Error handling

Duplicate assets

Asset relationships

Partial failures

Large result sets

Unexpected responses

Malformed data

Repeated scans
Full Workflow Tests

Example:

DOMAIN
    │
    ▼
DNS
    │
    ▼
IP
    │
    ▼
PORT
    │
    ▼
SERVICE
    │
    ▼
HTTP
    │
    ▼
TLS
    │
    ▼
ASSET CORRELATION

Verify that each stage produces valid input for the next stage.

Resource Protection Tests

Verify:

[ ] Concurrency limits work

[ ] Timeouts work

[ ] Redirect limits work

[ ] Crawl limits work

[ ] Response size limits work

[ ] Duplicate queue prevention works
Phase Complete When
[ ] Full system tests pass

[ ] Major failures are fixed

[ ] Resource limits work

[ ] Error handling is stable

[ ] Memory.md updated
PHASE 17 — PRODUCTION READINESS
Goal

Prepare the backend for real deployment.

Build

Add:

Production configuration

Environment separation

Database migrations

Logging configuration

Health checks

Monitoring readiness

Deployment configuration

Documentation review
Verify
[ ] No secrets committed

[ ] Configuration is externalized

[ ] Logs are useful

[ ] Internal errors are not exposed

[ ] Database configuration works

[ ] Health endpoint works

[ ] Application starts cleanly

[ ] Tests pass

[ ] Documentation is current
DEVELOPMENT STOP RULE

At any point, if a phase is not working correctly:

STOP
  ↓
IDENTIFY THE PROBLEM
  ↓
FIX THE CURRENT PHASE
  ↓
RETEST
  ↓
VERIFY
  ↓
ONLY THEN CONTINUE

Do not bypass broken functionality just to continue development.

MEMORY.md UPDATE FORMAT

After completing a phase, update Memory.md.

Example:

# Development Progress

Current Phase:
Phase 4 — Port Discovery Scanner

Status:
Completed

Completed Phases:
- Phase 0 — Project Foundation
- Phase 1 — Core Backend and Target Processing
- Phase 2 — Core Scan Models and Scanner Framework
- Phase 3 — DNS Scanner
- Phase 4 — Port Discovery Scanner

Current Tests:
- Unit tests: Passed
- Integration tests: Passed

Known Issues:
- None

Important Decisions:
- Python async networking used where appropriate
- Port state is separated from service identification
- Configurable timeout and concurrency limits added

Next Phase:
Phase 5 — Service Identification Scanner
FINAL DEVELOPMENT RULE

The AI must follow this sequence:

CURRENT PHASE
      │
      ▼
READ DOCUMENTATION
      │
      ▼
CHECK Memory.md
      │
      ▼
UNDERSTAND REQUIREMENTS
      │
      ▼
IMPLEMENT ONLY CURRENT PHASE
      │
      ▼
TEST
      │
      ├── FAILED
      │      │
      │      ▼
      │    FIX
      │      │
      │      └───────► TEST AGAIN
      │
      └── PASSED
             │
             ▼
      VERIFY OUTPUT
             │
             ▼
      UPDATE Memory.md
             │
             ▼
        NEXT PHASE

The system must never be developed like this:

BUILD EVERYTHING
      ↓
HOPE IT WORKS
      ↓
TRY TO DEBUG EVERYTHING

The correct approach is:

ONE PHASE
      ↓
ONE CLEAR GOAL
      ↓
BUILD
      ↓
TEST
      ↓
VERIFY
      ↓
COMPLETE
      ↓
NEXT PHASE