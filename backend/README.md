# Attack Surface Engineering Platform

## Overview

A modular backend **Attack Surface Engineering** platform.

The system accepts an authorized domain or IP address, performs defined direct requests against publicly reachable target infrastructure and DNS infrastructure, receives real responses, extracts and validates technical information, correlates discovered assets, and returns structured attack surface data.

**No information is fabricated. All results are evidence-based.**

---

## Architecture

- **Language:** Python 3.12+
- **Framework:** FastAPI
- **Architecture:** Modular Monolith
- **Scan approach:** Direct active scanning only

---

## Development

### Setup

```bash
# Create and activate virtual environment
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate

# Install development dependencies
pip install -r requirements/dev.txt

# Copy environment template
cp .env.example .env
```

### Run Development Server

```bash
uvicorn app.main:app --reload
```

API available at: `http://localhost:8000`

Health check: `GET http://localhost:8000/api/v1/health`

### Run Tests

```bash
pytest
```

---

## Project Documentation

All design and architecture documentation is in `docs/`:

| File | Purpose |
|---|---|
| `docs/PRD.md` | Product Requirements |
| `docs/Architecture.md` | Technical Architecture |
| `docs/Rules.md` | Development Rules and Coding Standards |
| `docs/Phases.md` | Development Phases and Roadmap |
| `docs/Design.md` | Design Reference |
| `docs/Memory.md` | Development Progress Tracker |

---

## Scan Tools (Planned)

| Phase | Tool |
|---|---|
| Phase 3 | DNS Scanner |
| Phase 4 | Port Discovery Scanner |
| Phase 5 | Service Identification Scanner |
| Phase 6 | HTTP/HTTPS Scanner |
| Phase 7 | Technology Detection Scanner |
| Phase 8 | Web Endpoint Discovery Scanner |
| Phase 9 | JavaScript Discovery Scanner |
| Phase 10 | TLS/Certificate Scanner |
| Phase 11 | Email Security Scanner |
| Phase 12 | Cloud/CDN Detection Scanner |

---

## Important Rules

- Every result must be traceable to real observed evidence.
- Failed requests return structured failure states — never fake data.
- Unknown is a valid and useful result.
- Accuracy is more important than producing more data.
