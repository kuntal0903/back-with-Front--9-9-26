# PRD.md

# Attack Surface Engineering Platform
## Backend-Only Direct Target Discovery Engine

**Document Version:** 1.0  
**Project Status:** Planning  
**Development Scope:** Backend Only  
**Primary Scope:** Direct / Active Target Requests  
**Target Use:** Authorized Security Assessment and Attack Surface Discovery

---

# 1. PROJECT OVERVIEW

## 1.1 Project Name

Attack Surface Engineering Platform

## 1.2 What Are We Building?

We are building a backend-only Attack Surface Engineering platform.

The system will accept a target from the user. The target can be:

- Domain
- Hostname
- IPv4 address
- IPv6 address

Examples:

```text
example.com
api.example.com
192.0.2.10
2001:db8::1

After receiving the target, the backend will analyze it and run one or more direct scanning tools.

The backend will send requests directly to:

DNS infrastructure
Target IP addresses
Open network ports
Network services
Web servers
Web applications
TLS servers
JavaScript hosting servers
CDN or publicly reachable infrastructure

The system will receive real responses, parse those responses, validate the discovered information, remove duplicates, connect related assets, and return structured attack surface information.

The project is not simply a collection of random scanners.

The system should behave like a controlled attack surface discovery engine.

The basic idea is:

USER ENTERS TARGET
        ↓
TARGET IS VALIDATED
        ↓
TARGET IS NORMALIZED
        ↓
RELEVANT SCAN TOOLS START
        ↓
TOOLS SEND DIRECT REQUESTS
        ↓
TARGET OR PUBLIC INFRASTRUCTURE RESPONDS
        ↓
RESPONSES ARE PARSED
        ↓
INFORMATION IS VALIDATED
        ↓
NEW ASSETS ARE DISCOVERED
        ↓
ASSETS ARE CORRELATED
        ↓
APPLICABLE NEW SCANS MAY START
        ↓
FINAL STRUCTURED ATTACK SURFACE OUTPUT
2. MAIN PROJECT OBJECTIVE

The main objective is to start with a domain name or IP address and discover as much publicly observable attack surface information as possible using direct requests.

The backend must be able to:

Accept a domain or IP address.
Validate the target.
Normalize the target.
Allow the user to select one scan.
Allow the user to select multiple scans.
Allow the user to run all applicable scans.
Send requests to the correct intended receiver.
Receive real responses.
Parse the responses correctly.
Extract useful technical information.
Validate discovered information.
Remove duplicate information.
Store evidence showing where every result came from.
Identify relationships between assets.
Discover new candidate assets.
Allow valid new assets to enter additional applicable scans.
Return structured results.
Never fabricate, guess, or invent scan results.
3. CURRENT PROJECT SCOPE

The first version focuses only on backend development and direct target scanning.

The current scope includes:

Direct target requests
Active scanning
DNS discovery
Network port discovery
Service identification
HTTP/HTTPS analysis
Technology detection
Web endpoint discovery
JavaScript discovery
Live TLS analysis
Email security analysis
Basic Cloud/CDN detection
Asset validation
Asset correlation
Evidence-based results

The initial version does not require third-party attack surface intelligence APIs.

4. CURRENT SCAN TOOLS

The project currently includes 10 direct scanning tools.

Tool 1: DNS Scan

Purpose:

Discover DNS information related to a domain or hostname.

Request is sent to:

DNS server or DNS resolver.

Response is provided by:

DNS infrastructure.

Possible information includes:

A records
AAAA records
CNAME records
MX records
NS records
TXT records
SOA records
TTL values when available
DNS response status

Example flow:

example.com
     ↓
DNS Scanner
     ↓
DNS Query
     ↓
DNS Resolver / DNS Server
     ↓
DNS Response
     ↓
Parse Records
     ↓
Validate Records
     ↓
Structured DNS Results
Tool 2: Port Discovery

Purpose:

Discover reachable network ports on an authorized target IP.

Request is sent to:

Target IP address.

Response is provided by:

Target operating system, network stack, firewall, or service behavior.

Possible information includes:

Target IP
Protocol
Port number
Reachability state
Open state
Closed state
Filtered or no definitive response
Error state
Scan timestamp

Example flow:

TARGET IP
     ↓
PORT SCANNER
     ↓
NETWORK CONNECTION / PROBE
     ↓
TARGET NETWORK STACK
     ↓
NETWORK RESPONSE
     ↓
INTERPRET RESPONSE
     ↓
PORT STATE
Tool 3: Service Identification

Purpose:

Identify the actual service or protocol running on a discovered reachable port.

Input:

IP address
Port number
Protocol

Request is sent to:

The service running on the target port.

Response is provided by:

The target service.

Possible information includes:

Protocol
Service type
Service banner
Protocol response
Service metadata
Detection evidence
Detection confidence

Important rule:

The tool must not identify a service only because of its port number.

Example:

Port 443 does not automatically mean HTTPS.

The service must respond in a way that supports the identification.

Example flow:

IP + PORT
     ↓
SERVICE IDENTIFIER
     ↓
PROTOCOL REQUEST / NEGOTIATION
     ↓
TARGET SERVICE
     ↓
SERVICE RESPONSE
     ↓
PARSE RESPONSE
     ↓
IDENTIFY SERVICE
     ↓
STORE EVIDENCE
Tool 4: HTTP/HTTPS Scan

Purpose:

Collect directly observable HTTP or HTTPS information.

Request is sent to:

Target URL or web server.

Response is provided by:

Web server
Web application
Reverse proxy
CDN
Other HTTP infrastructure

Possible information includes:

Requested URL
Final URL
Redirect chain
HTTP status code
HTTP status text
HTTP version
Response headers
Cookies
Content type
Content length
HTML title
HTML metadata
Response timing
Server information when actually returned

Example flow:

TARGET URL
     ↓
HTTP SCANNER
     ↓
HTTP / HTTPS REQUEST
     ↓
WEB SERVER
     ↓
HTTP RESPONSE
     ↓
PARSE HEADERS + BODY
     ↓
VALIDATE
     ↓
STRUCTURED WEB RESULTS
Tool 5: Technology Detection

Purpose:

Detect publicly observable technologies used by a web asset.

Input may include:

HTTP headers
HTML
Cookies
JavaScript references
Other collected web evidence

Possible information includes:

Web server indicators
Framework indicators
Frontend library indicators
CMS indicators
Reverse proxy indicators
CDN indicators
WAF indicators
Analytics or public script indicators

Every technology detection must contain:

Technology name
Detection method
Evidence
Confidence

Technology detection must never invent a technology.

Every detection must be based on an actual rule or observable evidence.

Example flow:

HTTP RESPONSE
HTML
HEADERS
JAVASCRIPT
     ↓
TECHNOLOGY DETECTOR
     ↓
MATCH AGAINST DEFINED RULES
     ↓
EVIDENCE FOUND?
     │
     ├── YES → DETECTION
     │
     └── NO → NO DETECTION
Tool 6: Web Endpoint Discovery

Purpose:

Discover publicly reachable paths, URLs, forms, and other web endpoints.

Request is sent to:

Target website or web application.

Response is provided by:

Web server or web application.

Discovery sources may include:

HTML links
Navigation links
Forms
robots.txt
sitemap.xml
Publicly linked resources

Possible information includes:

URL
Path
Query parameter names when observed
Source page
Response status
Content type
Parent asset

Every discovered endpoint must preserve information about where it was discovered.

Example flow:

TARGET WEBSITE
     ↓
WEB CRAWLER
     ↓
REQUEST PAGE
     ↓
WEB SERVER
     ↓
HTML RESPONSE
     ↓
EXTRACT LINKS / FORMS / RESOURCES
     ↓
NEW ENDPOINTS
     ↓
VALIDATE + DEDUPLICATE
Tool 7: JavaScript Discovery

Purpose:

Discover publicly accessible JavaScript files and extract relevant publicly visible references.

Request is sent to:

Target web server
CDN
JavaScript hosting infrastructure

Response is provided by:

Web server or CDN.

Possible information includes:

JavaScript file URLs
Script source URLs
Referenced URLs
Referenced API paths
Referenced hostnames
Referenced external domains
Additional JavaScript resources

Every discovered value must preserve:

Source JavaScript file
Extraction method
Original observed value

The system must distinguish between:

A directly extracted value
A possible pattern or inference

Example flow:

TARGET WEBSITE
     ↓
HTML SCAN
     ↓
DISCOVER SCRIPT TAGS
     ↓
REQUEST JAVASCRIPT FILE
     ↓
WEB SERVER / CDN
     ↓
JAVASCRIPT RESPONSE
     ↓
STATIC ANALYSIS
     ↓
EXTRACT REFERENCES
     ↓
VALIDATE + DEDUPLICATE
Tool 8: Live TLS Scan

Purpose:

Collect directly observable TLS and certificate information.

Input:

Hostname
Port

Example:

example.com:443

Request is sent to:

Target TLS server.

Response is provided by:

Target TLS infrastructure.

Possible information includes:

Certificate subject
Subject Alternative Names
Certificate issuer
Serial number
Validity start date
Validity end date
Certificate expiration
Certificate chain
Negotiated TLS version
Observed cipher information
Other directly observable TLS metadata

Example flow:

HOSTNAME + PORT
     ↓
TLS SCANNER
     ↓
TLS HANDSHAKE
     ↓
TARGET TLS SERVER
     ↓
TLS RESPONSE
     ↓
CERTIFICATE RECEIVED
     ↓
PARSE CERTIFICATE
     ↓
STRUCTURED TLS RESULTS
Tool 9: Email Security Scan

Purpose:

Analyze publicly available DNS information related to email infrastructure and email security.

Request is sent to:

DNS infrastructure.

Response is provided by:

DNS server or resolver.

Possible information includes:

MX records
SPF policy
DMARC policy
DKIM records when valid selectors are available
MTA-STS
TLS-RPT

Important rule:

The system must not claim that DKIM does not exist simply because no selector was found automatically.

The system must distinguish between:

Selector not tested
Selector tested
Record found
Record not found

Example flow:

DOMAIN
     ↓
EMAIL SECURITY SCANNER
     ↓
DNS QUERIES
     ↓
DNS SERVER
     ↓
DNS RESPONSES
     ↓
PARSE EMAIL RECORDS
     ↓
VALIDATE POLICIES
     ↓
STRUCTURED EMAIL SECURITY RESULTS
Tool 10: Basic Cloud/CDN Detection

Purpose:

Detect publicly observable indicators of cloud, CDN, reverse proxy, or similar infrastructure.

Input may include:

DNS results
HTTP results
TLS results
IP information

Evidence sources may include:

CNAME patterns
DNS response information
HTTP headers
TLS information
Defined infrastructure fingerprints

Every result must contain:

Detected infrastructure type
Possible provider when evidence supports it
Detection rule
Evidence
Confidence

The system must not claim a provider as confirmed without sufficient evidence.

Example flow:

DNS RESULTS
HTTP RESULTS
TLS RESULTS
     ↓
INFRASTRUCTURE DETECTOR
     ↓
CHECK DEFINED RULES
     ↓
MATCH FOUND?
     │
     ├── YES → PROVIDER / TYPE DETECTION
     │
     └── NO → NO CONFIRMED DETECTION
5. INFORMATION REQUIREMENT FOR EVERY TOOL

Every scan tool must clearly define all the information categories it can provide.

The system must never use vague descriptions such as:

DNS Scan gets DNS information.

Instead, every tool must document:

Information category
Specific data field
Source of the information
How the information is requested
Who provides the response
How the response is parsed
How the information is validated
Whether the result is confirmed or inferred
Evidence supporting the result

The general structure is:

TOOL
 │
 ├── INFORMATION CATEGORY 1
 │      ├── DATA FIELD
 │      ├── SOURCE
 │      └── VALIDATION
 │
 ├── INFORMATION CATEGORY 2
 │      ├── DATA FIELD
 │      ├── SOURCE
 │      └── VALIDATION
 │
 └── INFORMATION CATEGORY N
        ├── DATA FIELD
        ├── SOURCE
        └── VALIDATION
6. USER SCAN MODES

The user must be able to run scans in three ways.

Mode 1: Individual Scan

The user selects one tool.

Example:

Target: example.com
Scan: DNS Scan

Only the DNS Scan runs.

Mode 2: Multiple Selected Scans

The user selects several compatible tools.

Example:

Target: example.com

Selected:
- DNS Scan
- HTTP/HTTPS Scan
- TLS Scan
- Email Security Scan

Only those selected tools run.

Mode 3: Full Applicable Scan

The user selects:

Scan All Applicable

The backend determines which tools can run against the provided target.

Example:

example.com
     │
     ├── DNS Scan
     ├── HTTP/HTTPS Scan
     ├── TLS Scan
     ├── Email Security Scan
     └── Cloud/CDN Detection

If DNS discovers IP addresses:

IP ADDRESS
     │
     ├── Port Discovery
     │
     └── Service Identification

The scan manager determines the correct order.

7. MAIN BACKEND WORKFLOW

The complete system workflow should follow this structure:

USER INPUT
     │
     ▼
INPUT VALIDATION
     │
     ▼
TARGET NORMALIZATION
     │
     ▼
CREATE INITIAL ASSET
     │
     ▼
SCAN MANAGER
     │
     ├───────────────┬───────────────┐
     │               │               │
     ▼               ▼               ▼
INDIVIDUAL       SELECTED        FULL
SCAN             SCANS           SCAN
     │               │               │
     └───────────────┴───────────────┘
                     │
                     ▼
             START APPLICABLE
                SCAN TOOLS
                     │
                     ▼
              SEND REQUEST
                     │
                     ▼
            INTENDED RECEIVER
                     │
                     ▼
              RECEIVE RESPONSE
                     │
                     ▼
               PARSE RESPONSE
                     │
                     ▼
            EXTRACT INFORMATION
                     │
                     ▼
             VALIDATE RESULTS
                     │
                     ▼
             REMOVE DUPLICATES
                     │
                     ▼
           CREATE / UPDATE ASSETS
                     │
                     ▼
            CORRELATE RELATIONSHIPS
                     │
                     ▼
          NEW SCANNABLE ASSET FOUND?
                     │
              ┌──────┴──────┐
              │             │
             YES            NO
              │             │
              ▼             ▼
        VALIDATE SCOPE   FINAL RESULT
              │
              ▼
        RUN APPLICABLE
           NEXT SCAN
8. ASSET DISCOVERY PRINCIPLE

A discovered value must not automatically become a confirmed asset.

The process must be:

RAW DISCOVERY
     ↓
PARSE VALUE
     ↓
VALIDATE FORMAT
     ↓
NORMALIZE
     ↓
CHECK DUPLICATES
     ↓
CHECK SCOPE
     ↓
OPTIONAL CONFIRMATION
     ↓
CREATE OR UPDATE ASSET

Example:

A JavaScript file contains:

https://api.example.com

The system first records it as:

Discovered Reference
Source: JavaScript

It should not automatically claim that it is a reachable or confirmed service until validation is performed.

9. ASSET TYPES

The backend should support these initial asset types:

DOMAIN
HOSTNAME
IP_ADDRESS
DNS_RECORD
NETWORK_PORT
NETWORK_SERVICE
URL
WEB_APPLICATION
WEB_ENDPOINT
JAVASCRIPT_FILE
TLS_CERTIFICATE
EMAIL_CONFIGURATION
TECHNOLOGY
INFRASTRUCTURE_INDICATOR

Assets must be normalized.

Example:

Example.COM
example.com
EXAMPLE.com

These must not be stored as three different domain assets.

10. ASSET RELATIONSHIPS

The system must maintain relationships between assets.

Example:

example.com
     │
     │ resolves_to
     ▼
192.0.2.10
     │
     │ exposes
     ▼
443/tcp
     │
     │ provides
     ▼
HTTPS
     │
     │ serves
     ▼
https://example.com
     │
     │ contains
     ▼
/api

Possible relationships include:

DOMAIN → resolves_to → IP_ADDRESS

DOMAIN → has_record → DNS_RECORD

IP_ADDRESS → exposes → NETWORK_PORT

NETWORK_PORT → provides → NETWORK_SERVICE

NETWORK_SERVICE → serves → URL

URL → contains → WEB_ENDPOINT

WEB_PAGE → loads → JAVASCRIPT_FILE

HOSTNAME → presents → TLS_CERTIFICATE

DOMAIN → publishes → EMAIL_CONFIGURATION
11. MODULAR TOOL ARCHITECTURE REQUIREMENT

Every scan tool must be separate and independently identifiable.

Each tool must have its own implementation area.

Each tool should contain:

TOOL
 │
 ├── Main Tool Entry
 │
 ├── Working Logic
 │
 ├── Request Handler
 │
 ├── Response Parser
 │
 ├── Validator
 │
 ├── Output Model
 │
 └── Tests

The system must not place every scanner inside one large file.

Bad structure:

scanner.py

DNS
Ports
HTTP
TLS
JavaScript
Email
Everything

Required principle:

ONE TOOL
=
ONE CLEARLY SEPARATED MODULE

The exact folder structure will be defined in Architecture.md.

12. DEVELOPMENT METHOD

The project must be developed one tool at a time.

The required process is:

SELECT TOOL
     ↓
BUILD TOOL
     ↓
CREATE TESTS
     ↓
TEST VALID INPUT
     ↓
TEST INVALID INPUT
     ↓
TEST FAILURE CASES
     ↓
TEST TIMEOUT CASES
     ↓
VERIFY RESPONSE PARSING
     ↓
VERIFY RESULT ACCURACY
     ↓
VERIFY NO FABRICATED DATA
     ↓
FIX PROBLEMS
     ↓
MARK TOOL COMPLETE
     ↓
UPDATE Memory.md
     ↓
MOVE TO NEXT TOOL

A tool is not complete simply because the code runs.

A tool is complete only when:

Required functionality works
Tests pass
Error handling works
Response parsing is correct
Results are evidence-based
No fabricated information is returned
Completion status is recorded in Memory.md
13. BACKEND TECHNOLOGY

The recommended primary backend language is:

Python

Python is selected because it provides:

Strong networking support
DNS libraries
HTTP client libraries
TLS and certificate support
Asynchronous programming
Parsing tools
Good testing frameworks
Fast development speed
Good modular architecture support

The first version should avoid unnecessary complexity.

The project should not introduce multiple programming languages or unnecessary microservices unless a real technical requirement exists.

Exact framework, libraries, database, task system, and folder structure will be defined in:

Architecture.md
Rules.md
14. SCAN ORCHESTRATOR

The backend requires a central Scan Manager or Scan Orchestrator.

The Scan Orchestrator is responsible for:

Receiving the normalized target.
Determining the target type.
Determining the scan mode.
Selecting applicable tools.
Managing scan dependencies.
Starting scan tools.
Collecting scan results.
Handling scan failures.
Processing newly discovered assets.
Preventing unnecessary repeated scans.
Tracking overall scan progress.
Producing final structured results.

Individual scan tools must not control the entire system.

The Scan Orchestrator controls the overall workflow.

15. REQUEST AND RESPONSE REQUIREMENT

Every tool must clearly define its complete communication process.

The required pattern is:

USER INPUT
     ↓
INPUT VALIDATION
     ↓
NORMALIZED INPUT
     ↓
REQUEST CONSTRUCTION
     ↓
REQUEST SENT TO INTENDED RECEIVER
     ↓
RECEIVER PROCESSES REQUEST
     ↓
RESPONSE RECEIVED
     ↓
RAW RESPONSE PARSED
     ↓
INFORMATION EXTRACTED
     ↓
RESULT VALIDATED
     ↓
STRUCTURED OUTPUT CREATED
     ↓
EVIDENCE STORED

Every tool must know exactly:

What input it accepts
What request it sends
Where the request goes
Who responds
What type of response is expected
How the response is parsed
What information can be extracted
How the result is validated
16. ACCURACY AND EVIDENCE RULE

The project must prioritize:

Accuracy
Evidence
Traceability
Deterministic processing
Honest failure states

Every result must come from:

A real response from the target.
A real response from public infrastructure responsible for answering the request.
Deterministic parsing of a received response.
Deterministic analysis of collected evidence.
A clearly labeled inference supported by evidence.

The system must distinguish between:

CONFIRMED

and:

DETECTED / INFERRED

Example:

Confirmed:
Port 443 responded successfully.

Evidence:
Actual network response.

Example:

Detected:
Possible CDN.

Evidence:
Matching DNS pattern and HTTP headers.

Confidence:
Medium.

The system must never convert a possible result into a confirmed result without sufficient evidence.

17. NO RANDOM OR FABRICATED RESULTS

This is one of the most important project rules.

The system must never:

Generate fake scan results
Invent IP addresses
Guess hostnames
Guess open ports
Guess technologies
Invent service names
Add sample data to real scan results
Return hardcoded success information
Replace failed requests with fake information

If information cannot be determined, the system must return a real state such as:

Not Tested
No Response
Unknown
Not Detected
Unable to Determine
Request Failed

These states must not be confused with:

Confirmed Absent
18. ERROR HANDLING

Every tool must handle:

Invalid input
DNS failure
Connection failure
Connection timeout
TLS failure
Malformed response
Unexpected response
Unsupported protocol
Parser failure
Internal tool error

A failed request must never result in fabricated information.

Correct behavior:

REQUEST FAILED
     ↓
CAPTURE ERROR
     ↓
RETURN STRUCTURED FAILURE STATE

Example:

{
  "status": "failed",
  "error_type": "connection_timeout",
  "message": "Target did not respond within the configured timeout."
}
19. STRUCTURED OUTPUT

Every tool must return structured data.

Each result should contain information similar to:

{
  "scan_id": "scan_identifier",
  "tool": "tool_name",
  "status": "completed",
  "target": {
    "original": "example.com",
    "normalized": "example.com",
    "type": "domain"
  },
  "results": [],
  "evidence": [],
  "errors": [],
  "started_at": "timestamp",
  "completed_at": "timestamp"
}

The exact schema may differ between tools.

However, every result should preserve:

What was found
Where it came from
How it was found
Which tool found it
Evidence
Confidence when applicable
Timestamp
20. MEMORY.md REQUIREMENT

Memory.md will be used to track development progress.

It must record:

Current development phase
Current tool being built
Completed tools
Tools under development
Test status
Known issues
Architecture decisions
Dependency decisions
Important project constraints
Next development task

Example:

Current Tool:
DNS Scan

Implementation:
Completed

Unit Tests:
Passed

Integration Tests:
Passed

Accuracy Review:
Passed

Status:
Complete

Next Tool:
Port Discovery

A tool must not be considered complete until its development state is properly recorded.

21. PROJECT LIMITATIONS

The system must not claim that it can always discover 100% of every target's attack surface.

Direct scanning has limitations.

Examples include:

Firewalls
WAFs
CDNs
Reverse proxies
Authentication
Rate limiting
Dynamic applications
Location-dependent DNS
Hidden infrastructure
Private infrastructure
Temporarily unavailable services
Different responses over time

The correct project objective is:

Discover and accurately represent the information observable through the configured direct scanning process at the time of the scan.

The system must preserve:

What was observed
How it was observed
When it was observed
Which tool observed it
What evidence supports it
22. AUTHORIZED USE

The platform is intended for authorized security testing and asset discovery.

The system should support the concept of:

Target
Scope
Scan ID
Scan configuration
Selected scan type
Timestamp
Scan status

Newly discovered assets should be checked against the configured scope before automatically receiving additional active scans.

23. PROJECT SUCCESS CRITERIA

Version 1 is successful when the backend can:

Accept a domain or IP address.
Validate and normalize the target.
Run one scan independently.
Run multiple selected scans.
Run all applicable scans.
Execute all 10 defined direct scanning tools.
Send requests to the correct intended receiver.
Correctly parse real responses.
Return structured information.
Preserve evidence.
Avoid fabricated results.
Clearly represent errors and unknown states.
Discover new candidate assets.
Validate and deduplicate discovered assets.
Maintain relationships between assets.
Support controlled additional scanning of discovered assets.
Keep every tool independently identifiable.
Test each tool separately.
Build tools one by one.
Track development progress through Memory.md.
24. FINAL PRODUCT DEFINITION

The first version of this project is:

A modular backend Attack Surface Engineering platform that accepts an authorized domain or IP address, performs defined direct requests against publicly reachable target infrastructure and DNS infrastructure, receives real responses, extracts and validates technical information, prevents fabricated results, correlates discovered assets, and returns structured attack surface information.

The complete workflow is:

USER INPUT
     ↓
VALIDATE
     ↓
NORMALIZE
     ↓
SELECT SCAN MODE
     ↓
SCAN ORCHESTRATOR
     ↓
START APPLICABLE TOOL
     ↓
SEND DIRECT REQUEST
     ↓
INTENDED RECEIVER
     ↓
REAL RESPONSE
     ↓
PARSE RESPONSE
     ↓
EXTRACT INFORMATION
     ↓
VALIDATE RESULT
     ↓
STORE EVIDENCE
     ↓
DEDUPLICATE
     ↓
CREATE / UPDATE ASSET
     ↓
CORRELATE ASSETS
     ↓
NEW SCANNABLE ASSET?
     │
 ┌───┴────┐
 │        │
YES       NO
 │        │
 ▼        ▼
CONTINUE   FINAL OUTPUT
25. MOST IMPORTANT PROJECT RULE

The system must never try to appear intelligent by adding information that was not actually discovered.

The value of the platform depends on:

Real evidence
Accurate parsing
Logical validation
Clear relationships
Honest limitations
No fabricated data

The guiding principle is:

Every result must be traceable to real observed evidence, deterministic processing, or a clearly labeled evidence-supported inference.