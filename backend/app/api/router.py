"""
app/api/router.py

Central API router.

All route groups are registered here and included into the FastAPI app
in app/main.py. This keeps main.py clean and makes it easy to add
or reorganize routes in future phases.
"""

from fastapi import APIRouter

from app.api.routes import health, scans

api_router = APIRouter()

# Health check — always mounted
api_router.include_router(health.router)

# Scan management — stub routes registered, implementation deferred to Phase 1+
api_router.include_router(scans.router)
