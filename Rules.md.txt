# Rules.md

# Attack Surface Engineering Platform
## AI Development Rules, Coding Standards, and Engineering Guardrails

**Document Version:** 1.0  
**Project Scope:** Backend Only  
**Primary Language:** Python 3.12+  
**Architecture:** Modular Monolith  
**Development Approach:** Build → Test → Verify → Continue

---

# 1. PURPOSE OF THIS DOCUMENT

This document defines the strict rules that must be followed by any AI assistant or developer working on this project.

The purpose is to prevent:

- Random code generation
- Unnecessary complexity
- Fake scan results
- Unsupported assumptions
- Incorrect cybersecurity logic
- Mixing unrelated scan logic
- Breaking previously working modules
- Building too many features at once
- Adding unnecessary libraries
- Skipping tests
- Continuing development when the current tool is not working

The main rule is:

```text
DO NOT GUESS.
DO NOT INVENT RESULTS.
DO NOT ASSUME A SCAN WORKED WITHOUT EVIDENCE.

This project must prioritize:

ACCURACY
↓
VERIFICATION
↓
TRACEABILITY
↓
RELIABILITY
↓
PERFORMANCE
↓
CONVENIENCE
2. CORE DEVELOPMENT PRINCIPLE

The AI must follow this workflow:

UNDERSTAND
    ↓
PLAN
    ↓
BUILD ONE SMALL COMPONENT
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
UPDATE MEMORY.md
    ↓
MOVE TO NEXT COMPONENT

The AI must NOT follow this workflow:

BUILD EVERYTHING
    ↓
ASSUME IT WORKS
    ↓
MOVE ON
3. PRIMARY RULE: BUILD ONE TOOL AT A TIME

Only one scanner should be actively developed at a time unless explicitly instructed otherwise.

Correct workflow:

1. Select one scan module

2. Understand its exact purpose

3. Define its input

4. Define its intended receiver

5. Define the request mechanism

6. Define the expected response

7. Build the scanner

8. Test the scanner

9. Verify the returned information

10. Fix errors

11. Retest

12. Mark the module complete

13. Update Memory.md

14. Move to the next module

Do not begin implementing the next scanner until the current scanner is reasonably working and tested.

4. NO RANDOM OR FAKE RESULTS

The system must never generate fake information.

Forbidden:

If DNS does not respond:
    return random IP address

If technology cannot be detected:
    guess Apache or nginx

If service cannot be identified:
    assume HTTP

If certificate parsing fails:
    invent certificate information

Correct behavior:

DNS result unavailable:
    status = failed

Technology cannot be confirmed:
    status = unknown

Service cannot be identified:
    status = unknown

Certificate parsing fails:
    status = parser_error

The system must distinguish:

CONFIRMED
DETECTED
INFERRED
UNKNOWN
NOT DETECTED
FAILED
NOT TESTED

Never represent unknown as confirmed.

5. EVERY RESULT MUST HAVE A SOURCE

Every meaningful result must identify where it came from.

Example:

{
  "value": "example value",
  "source_tool": "dns_scan",
  "discovery_method": "dns_query",
  "status": "confirmed"
}

For important results, preserve evidence when technically reasonable.

Example:

{
  "technology": "nginx",
  "status": "detected",
  "evidence": {
    "type": "http_header",
    "name": "server",
    "value": "nginx"
  }
}

Do not return:

Technology: nginx

without recording how the conclusion was reached.

6. DO NOT CONFUSE REQUEST SUCCESS WITH INFORMATION ACCURACY

A successful network request does not automatically mean the extracted information is correct.

Example:

HTTP Request
    │
    ▼
200 OK
    │
    ▼
DO NOT AUTOMATICALLY TRUST EVERYTHING
    │
    ▼
PARSE RESPONSE
    │
    ▼
VALIDATE DATA
    │
    ▼
RETURN VERIFIED INFORMATION

The rule is:

REQUEST SUCCESS
≠
RESULT CONFIRMATION
7. INPUT VALIDATION IS REQUIRED

Every scanner must validate its input before making a network request.

Examples:

DNS Scanner:
    Valid domain or hostname required

Port Scanner:
    Valid IP address or approved hostname required

HTTP Scanner:
    Valid URL or hostname required

TLS Scanner:
    Valid hostname/IP + valid port required

Invalid input must return a structured error.

Example:

{
  "status": "failed",
  "error_type": "invalid_input",
  "message": "Target is not a valid hostname or IP address."
}

Do not silently modify invalid input into a different target.

8. TARGET NORMALIZATION IS REQUIRED

All targets must be normalized before scanning.

Example:

Example.COM
example.com.
EXAMPLE.com

Normalized:

example.com

The system should preserve both:

original_target
normalized_target

Do not lose the original user input.

9. EVERY SCANNER MUST HAVE A CLEAR RESPONSIBILITY

One scanner must perform one primary job.

Correct:

DNS Scanner
    → DNS records

Port Scanner
    → Reachability of authorized ports

HTTP Scanner
    → HTTP response information

TLS Scanner
    → TLS handshake and certificate information

Incorrect:

scanner.py
    → DNS
    → Ports
    → HTTP
    → TLS
    → JavaScript
    → Database
    → Random helper logic

Do not create "god files."

10. EVERY SCANNER MUST HAVE ITS OWN DIRECTORY

Required structure:

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

Each scanner must keep its own logic isolated.

Example:

scanners/dns/
│
├── scanner.py
├── query.py
├── parser.py
├── validator.py
├── models.py
└── tests/

Do not place DNS-specific code inside:

scanners/http/

Do not place HTTP-specific code inside:

scanners/dns/
11. USE A COMMON SCANNER INTERFACE

All scanners should follow a predictable lifecycle.

Conceptually:

validate_input()
    ↓
execute()
    ↓
parse_response()
    ↓
validate_result()
    ↓
build_result()

The internal implementation may differ, but the external behavior should remain consistent.

12. REQUEST AND RESPONSE LOGIC MUST BE EXPLICIT

Before implementing a scanner, clearly define:

INPUT
    ↓
WHO RECEIVES THE REQUEST?
    ↓
WHAT REQUEST IS SENT?
    ↓
WHAT RESPONSE IS EXPECTED?
    ↓
HOW IS THE RESPONSE PARSED?
    ↓
HOW IS THE RESULT VALIDATED?
    ↓
WHAT STRUCTURED OUTPUT IS RETURNED?

Example:

DNS SCAN

Input:
example.com

Receiver:
DNS server

Request:
DNS query for A record

Response:
DNS response

Parser:
Extract A records

Validation:
Verify valid IPv4 format

Output:
Confirmed IP addresses

The AI must understand this flow before writing the implementation.

13. USE REAL NETWORK RESPONSES

Scan results must come from actual received data.

The system may use:

DNS responses
TCP connection results
Protocol negotiation
HTTP responses
HTTP headers
HTML documents
JavaScript files
TLS certificates
TLS handshake information

The system must not create output based only on assumptions.

Example:

Wrong:

Port 443 is usually HTTPS.
Therefore:
Service = HTTPS

Better:

Port 443 reachable
    ↓
Perform protocol/service verification
    ↓
If TLS/HTTP behavior confirms it:
    Service = HTTPS

Port numbers are evidence only for common expectations, not proof of service identity.

14. NO HARDCODED SCAN RESULTS

Forbidden:

return {
    "server": "nginx"
}

unless that value was actually extracted from the target response or intentionally provided as a test fixture.

Allowed:

server = response.headers.get("server")

Then:

Validate
    ↓
Store
    ↓
Return

Hardcoded values may only be used in:

Unit tests
Fixtures
Mock responses
Explicit configuration
15. LIBRARY RULES

Use established libraries where they provide reliable protocol handling.

Recommended categories include:

FastAPI
    API layer

Pydantic
    Input and output validation

httpx
    HTTP/HTTPS requests

dnspython
    DNS operations

Python ssl module
    TLS operations

Python socket module
    Basic network connections

ipaddress
    IP validation and processing

SQLAlchemy
    Database interaction

pytest
    Testing

Use the standard library when it is sufficient.

Do not install a library simply to avoid writing a small amount of simple code.

16. LIBRARIES TO AVOID

Do not introduce libraries that:

Duplicate existing functionality without a clear benefit
Are unmaintained
Have unclear security status
Add unnecessary complexity
Hide critical logic that needs to be understood
Require external services for basic direct scanning
Are installed only because an AI "thinks it might be useful"

Before adding a dependency, ask:

1. Is it necessary?

2. Does Python already provide this capability?

3. Is an existing project dependency sufficient?

4. Is the library actively maintained?

5. Does it improve reliability enough to justify the dependency?

If the answer is no, do not add it.

17. DO NOT ADD THIRD-PARTY DATA SOURCES WITHOUT APPROVAL

The current project scope focuses on direct target scanning.

Therefore, do not automatically add:

Shodan
Censys
VirusTotal
SecurityTrails
WhoisXML
ZoomEye
BinaryEdge

or any other external intelligence provider.

Do not silently add:

API keys
External API calls
Paid services
Scraping dependencies

Direct scanning means the backend communicates with:

DNS infrastructure
Target network services
Target web servers
Target TLS services

External intelligence may be added later as a separate integration layer.

18. DO NOT SCRAPE RANDOM WEBSITES FOR DATA

Do not collect attack surface information from arbitrary search engines, websites, or pages unless that source is intentionally added to the project design.

The system should not depend on:

Random Google search
Random web scraping
Undocumented APIs
Unofficial services
Unverified data sources
19. TIMEOUTS ARE REQUIRED

Every network operation must have a timeout.

Never allow:

request()
    ↓
wait forever

Correct:

request()
    ↓
timeout
    │
    ├── response received
    │
    └── timeout error

Timeouts should be configurable.

Do not use the same timeout blindly for every operation.

Different operations may require different timeout profiles.

20. RETRIES MUST BE CONTROLLED

Do not retry forever.

Bad:

FAIL
 ↓
RETRY
 ↓
FAIL
 ↓
RETRY FOREVER

Correct:

REQUEST
   │
   ├── SUCCESS
   │
   └── TEMPORARY FAILURE
            │
            ▼
       LIMITED RETRY
            │
            ├── SUCCESS
            │
            └── FINAL FAILURE

Retries should only be used for failures that may reasonably be temporary.

Do not blindly retry:

Invalid input
Unsupported protocol
Parser logic error
Scope rejection
21. CONCURRENCY MUST BE LIMITED

The system may execute independent operations concurrently, but concurrency must be controlled.

Never do:

Create unlimited tasks

Use:

Maximum concurrent operations
Connection limits
Per-scan limits
Timeouts
Resource monitoring

The goal is:

FAST
BUT
CONTROLLED

not:

MAXIMUM POSSIBLE REQUESTS
22. DO NOT BLOCK THE ENTIRE BACKEND

Network operations can take time.

Use asynchronous operations where appropriate.

Do not allow one slow target to freeze unrelated API requests.

Long-running scans should execute outside the request-response lifecycle when necessary.

23. ERROR HANDLING MUST BE STRUCTURED

Do not return vague errors such as:

Something went wrong
Error
Failed

Use structured errors.

Example:

{
  "status": "failed",
  "error_type": "connection_timeout",
  "tool": "http_scan",
  "target": "example.com"
}

Possible error categories:

invalid_input
invalid_target
scope_rejected
dns_error
connection_error
connection_timeout
tls_error
http_error
invalid_response
parser_error
dependency_error
internal_error
24. NEVER HIDE ERRORS

Do not do this:

try:
    run_scan()
except Exception:
    pass

Every failure must be:

Handled
Classified
Recorded
Returned or logged appropriately

Do not silently ignore exceptions.

25. DO NOT USE BROAD EXCEPTION HANDLING WITHOUT CLASSIFICATION

Avoid:

except Exception:
    return "failed"

Prefer:

Specific expected exception
    ↓
Specific handling

Unexpected exception
    ↓
Safe internal error
    ↓
Structured logging

Unexpected exceptions must not expose internal secrets or stack traces to API users.

26. VALIDATE RESULTS AFTER PARSING

A response may be received successfully but still contain invalid or malformed data.

Correct flow:

RECEIVE RESPONSE
        ↓
PARSE
        ↓
EXTRACT VALUE
        ↓
VALIDATE FORMAT
        ↓
VALIDATE CONTEXT
        ↓
RETURN RESULT

Example:

DNS Response
    ↓
Extract IP
    ↓
Validate IP format
    ↓
Store confirmed result
27. PRESERVE RAW EVIDENCE WHEN REASONABLE

Important results should preserve enough evidence for debugging and verification.

Examples:

HTTP Header
Certificate field
DNS record
Protocol response
Detection rule

Do not unnecessarily store massive raw responses when only a small evidence field is required.

The principle is:

STORE ENOUGH TO VERIFY
NOT EVERYTHING FOREVER
28. DO NOT OVERSTATE CONFIDENCE

Use clear confidence levels.

Example:

HIGH
    Direct protocol response or explicit evidence

MEDIUM
    Multiple supporting indicators

LOW
    Weak or indirect indicator

Do not mark inferred information as high confidence without strong evidence.

29. UNKNOWN IS A VALID RESULT

The system must support:

unknown

Example:

Technology:
unknown

is better than:

Technology:
Apache

when Apache was never actually confirmed.

The system should prefer:

NO VERIFIED ANSWER

over:

INCORRECT ANSWER
30. DEDUPLICATE RESULTS

The same asset may be discovered multiple times.

Example:

DNS
    ↓
api.example.com

TLS
    ↓
api.example.com

JavaScript
    ↓
api.example.com

Do not create three unrelated assets.

Create:

api.example.com

Sources:
- dns_scan
- tls_scan
- javascript_scan

Preserve all discovery sources.

31. DO NOT LOSE ASSET RELATIONSHIPS

Assets must retain relationships.

Example:

example.com
     │
     │ resolves_to
     ▼
192.0.2.10

Another example:

192.0.2.10
     │
     │ exposes
     ▼
443
     │
     │ serves
     ▼
HTTPS

Do not return only a flat list when relationship data is available.

32. NEW ASSETS MUST PASS THROUGH VALIDATION

When a scanner discovers a new asset:

NEW ASSET
    ↓
VALIDATE FORMAT
    ↓
NORMALIZE
    ↓
CHECK DUPLICATE
    ↓
CHECK SCOPE
    ↓
STORE
    ↓
OPTIONALLY QUEUE

Do not immediately perform additional scanning without checking whether the asset is allowed and applicable.

33. PREVENT INFINITE SCAN LOOPS

The system must track:

asset
+
scan_type
+
status

Example:

example.com + dns_scan + completed

Do not repeatedly run the same completed scan unless explicitly requested.

34. ONE TOOL FAILURE MUST NOT DESTROY THE ENTIRE SCAN

Example:

DNS      → Completed
HTTP     → Completed
TLS      → Timeout
Email    → Completed

Overall scan status should be:

partial_failure

not automatically:

failed

The final output must preserve successful results.

35. DO NOT MODIFY WORKING MODULES WITHOUT REASON

If a scanner is already tested and working:

Do not rewrite it while building an unrelated scanner.

Before changing existing code:

1. Identify why the change is necessary

2. Identify affected modules

3. Make the smallest possible change

4. Run relevant tests

5. Verify existing behavior

Avoid unnecessary refactoring.

36. TEST BEFORE MOVING FORWARD

A component is not complete because the code exists.

A component is complete only when:

Code exists
    +
Tests exist
    +
Tests pass
    +
Expected output is verified
    +
Error cases are tested

Only then:

UPDATE Memory.md

and move forward.

37. TEST REALISTIC CASES

Each scanner should test at least:

1. Valid target

2. Invalid target

3. Valid response

4. No response

5. Timeout

6. Malformed response

7. Duplicate result

8. Unexpected response

9. Structured error

10. Structured successful output

Tests should not depend entirely on random public targets.

Use controlled fixtures and test environments where possible.

38. SEPARATE UNIT TESTS AND INTEGRATION TESTS

Unit tests should test:

Parsing
Validation
Normalization
Data transformation
Detection rules

Integration tests should test:

Actual scanner flow
Network communication
Request generation
Response handling

Do not confuse the two.

39. CONFIGURATION MUST NOT BE HARDCODED

Do not hardcode:

Timeouts
Concurrency limits
Database URLs
Secrets
API keys
Environment-specific settings

Use configuration.

Example:

environment variables
configuration files
application settings

Never commit secrets.

40. LOGGING RULES

Every important operation should log useful context.

Include when appropriate:

scan_id
tool_name
target
asset_id
event
status
timestamp

Example:

scan_id=123
tool=dns
target=example.com
event=query_started
status=running

Do not log:

Passwords
Secrets
API keys
Sensitive authorization headers
41. DO NOT EXPOSE INTERNAL DETAILS TO USERS

API responses should not expose:

Internal file paths
Stack traces
Database credentials
Environment variables
Internal IP architecture
Secrets

Detailed errors may be logged internally.

External users receive safe structured errors.

42. TYPE SAFETY AND DATA MODELS

All major inputs and outputs should use explicit models.

Do not pass uncontrolled dictionaries everywhere.

Prefer:

ScanRequest
ScanResult
Asset
Evidence
ErrorResponse

The system should have predictable schemas.

43. DO NOT MIX BUSINESS LOGIC WITH API ROUTES

API routes should remain thin.

Bad:

POST /scan
    │
    ├── Validate target
    ├── Run DNS
    ├── Run ports
    ├── Parse HTTP
    ├── Save database
    └── Return everything

Correct:

API Route
    ↓
Service
    ↓
Orchestrator
    ↓
Scanner
    ↓
Result Processing
44. DO NOT MIX DATABASE LOGIC WITH SCANNER LOGIC

A scanner should primarily:

Receive input
    ↓
Perform scan
    ↓
Parse response
    ↓
Validate result
    ↓
Return structured data

Database storage should be handled separately.

45. KEEP FUNCTIONS SMALL AND CLEAR

Avoid functions that do:

Input validation
+
Network request
+
Response parsing
+
Database storage
+
Logging
+
Asset creation

in one large function.

Prefer:

validate_input()

build_request()

send_request()

parse_response()

validate_result()

build_result()

Each function should have a clear responsibility.

46. USE CLEAR NAMES

Bad:

do_it()
process()
handle()
data2()
temp()
x()

Better:

validate_target()
query_dns_record()
parse_certificate()
extract_http_headers()
deduplicate_assets()

Names should explain their purpose.

47. DO NOT CREATE CODE JUST FOR "FUTURE POSSIBILITY"

Do not build speculative features.

Example:

Maybe we need Kubernetes later
    → Do not add Kubernetes now

Maybe we need microservices later
    → Do not create microservices now

Maybe we need ten databases later
    → Do not add them now

Build what the current phase requires.

48. KEEP THE ARCHITECTURE SIMPLE

Preferred:

Simple
Modular
Understandable
Testable

Avoid:

Complex
Over-engineered
Unnecessary abstraction
Unnecessary services

The question before adding complexity is:

What real problem does this solve right now?

If there is no clear answer, do not add it.

49. SECURITY RULES

The system itself must be secure.

Requirements:

Validate all input

Do not trust client data

Protect secrets

Use safe configuration

Limit resource usage

Handle network errors safely

Avoid exposing internal information

Control concurrent scanning

Record important events

Use scope restrictions where required
50. SCOPE AND AUTHORIZATION RULE

Active scanning must be designed for authorized targets and defined scope.

The system must support scope restrictions before performing active network operations.

The architecture must allow:

Allowed targets

Allowed domains

Allowed IP ranges

Excluded targets

The scope decision should occur before active scanning.

51. RESOURCE PROTECTION RULE

The scanner must protect itself from excessive resource consumption.

Use controls for:

Maximum scan duration

Maximum concurrent connections

Maximum queued assets

Maximum crawl depth

Maximum response size where appropriate

Maximum redirect count

Maximum processing limits

Do not allow one scan to consume unlimited resources.

52. REDIRECT HANDLING RULE

HTTP redirects must be controlled.

The scanner must:

Track redirects

Limit redirect count

Record final destination

Avoid infinite redirect loops

Do not blindly follow redirects forever.

53. RESPONSE SIZE LIMIT RULE

The scanner should not automatically load unlimited amounts of data.

Where appropriate:

Define maximum response size

Stop excessive downloads

Record truncation if necessary

The system must protect itself from unexpectedly large responses.

54. PARSER RULE

Parsers must assume external responses may be malformed.

Never assume:

Response always contains expected fields.

Correct:

Check field exists
    ↓
Check type
    ↓
Validate format
    ↓
Process safely
55. DETECTION RULES MUST BE EXPLICIT

Technology detection and similar analysis must use clear rules.

Example:

Evidence:
Server header contains nginx

Rule:
Header fingerprint

Result:
nginx detected

Confidence:
High

Do not create unexplained detection conclusions.

Detection logic should be reviewable.

56. DO NOT CLAIM COMPLETE DISCOVERY

The system must not claim:

All attack surfaces discovered
100% complete discovery
No other assets exist

The correct wording in system results should reflect reality.

Example:

Assets discovered through the configured scan methods.

The system can provide:

OBSERVED ATTACK SURFACE

not guaranteed complete global knowledge.

57. SCAN MODULE COMPLETION CHECKLIST

Before marking a scanner complete, verify:

[ ] Scanner purpose is defined

[ ] Input model exists

[ ] Input validation exists

[ ] Target normalization is correct

[ ] Intended receiver is documented

[ ] Request mechanism is implemented

[ ] Timeout exists

[ ] Retry behavior is controlled

[ ] Response parser exists

[ ] Result validation exists

[ ] Structured output exists

[ ] Structured errors exist

[ ] Evidence is preserved where applicable

[ ] Unit tests exist

[ ] Integration tests exist where appropriate

[ ] Tests pass

[ ] Realistic output has been reviewed

[ ] No fake or hardcoded production result exists

[ ] Documentation is updated

[ ] Memory.md is updated

Do not mark the scanner as complete if major checklist items are missing.

58. MEMORY.md UPDATE RULE

After every completed milestone, update:

docs/Memory.md

The update must contain:

Current phase

Current module

Completed modules

Current status

Tests completed

Known issues

Important technical decisions

Next task

Example:

# Development Status

Current Phase:
Phase 2

Current Module:
DNS Scanner

Status:
Completed

Tests:
Unit tests passed
Integration tests passed

Known Issues:
None currently known

Important Decisions:
- Uses dnspython
- Structured DNS result model
- Configurable timeout

Next Task:
Implement Port Discovery Scanner

Memory.md must describe the real state of development.

Do not mark unfinished work as completed.

59. WHEN THE AI IS UNCERTAIN

If the AI does not have enough information to make a reliable implementation decision, it must not silently guess.

The AI should:

1. Identify the uncertainty

2. Check existing project documentation

3. Check Architecture.md

4. Check Rules.md

5. Check Phases.md

6. Check Memory.md

7. Inspect relevant existing code

8. Make the smallest justified decision

Do not introduce major architecture changes based on unsupported assumptions.

60. BEFORE WRITING NEW CODE

The AI should first determine:

What module is currently being built?

What does Memory.md say?

What phase is active?

What files already exist?

What interface does the new module need?

What inputs are required?

Who receives the network request?

What response is expected?

How will the response be validated?

How will errors be represented?

How will the module be tested?

Only then should implementation begin.

61. FINAL MASTER RULE

Every development decision should follow this principle:

REAL INPUT
    ↓
VALIDATE
    ↓
REAL REQUEST
    ↓
INTENDED RECEIVER
    ↓
REAL RESPONSE
    ↓
PARSE
    ↓
VALIDATE
    ↓
PRESERVE EVIDENCE
    ↓
STRUCTURED RESULT

The system must never become:

INPUT
    ↓
GUESS
    ↓
OUTPUT

The preferred behavior is:

ACCURATE RESULT

If that is not possible:

UNKNOWN

If the operation fails:

STRUCTURED FAILURE

Never replace missing knowledge with invented information.

62. FINAL AI INSTRUCTION

You are building a cybersecurity-focused Attack Surface Engineering backend.

Your job is not to produce the maximum amount of code as quickly as possible.

Your job is to build a system that is:

MODULAR

EVIDENCE-BASED

TESTABLE

TRACEABLE

SAFE

ACCURATE

EASY TO DEBUG

EASY TO EXTEND

Always follow:

ONE COMPONENT
    ↓
BUILD
    ↓
TEST
    ↓
VERIFY
    ↓
FIX
    ↓
RETEST
    ↓
UPDATE MEMORY
    ↓
NEXT COMPONENT

Never assume that code works because it compiles.

Never assume that a network response proves the extracted information.

Never invent scan results.

Never hide errors.

Never silently ignore failures.

Never unnecessarily change working modules.

Never add unnecessary complexity.

Always prefer:

REAL EVIDENCE
OVER
ASSUMPTION

and:

UNKNOWN
OVER
INCORRECT