"""
app/main.py

FastAPI application entry point for the Attack Surface Engineering Platform.

This module:
  - Creates the FastAPI application instance
  - Configures logging on startup
  - Registers all API routes under the /api/v1 prefix
  - Registers global exception handlers for clean error responses
  - Exposes the app object for uvicorn

Usage:
    uvicorn app.main:app --reload
"""

from contextlib import asynccontextmanager
from typing import AsyncGenerator

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.api.router import api_router
from app.core.config import settings
from app.core.constants import PROJECT_NAME, PROJECT_VERSION, API_PREFIX
from app.core.db import mongo_manager
from app.core.exceptions import AttackSurfaceEngineError
from app.core.logging import configure_logging, get_logger

# ─────────────────────────────────────────────
# Configure logging before the app object is created
# so startup messages are captured correctly.
# ─────────────────────────────────────────────
configure_logging()
logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(application: FastAPI) -> AsyncGenerator[None, None]:
    """
    FastAPI lifespan context manager.

    Code before the `yield` runs on startup.
    Code after the `yield` runs on shutdown.
    """
    # ── Startup ──────────────────────────────
    logger.info(
        "Application starting — project=%s version=%s environment=%s",
        PROJECT_NAME,
        PROJECT_VERSION,
        settings.app_env,
    )
    try:
        await mongo_manager.connect()
    except Exception as e:
        logger.error("MongoDB startup connection error: %s", e)

    yield  # Application is running

    # ── Shutdown ─────────────────────────────
    logger.info("Application shutting down")
    try:
        await mongo_manager.disconnect()
    except Exception as e:
        logger.error("MongoDB shutdown error: %s", e)


def create_application() -> FastAPI:
    """
    Factory function that creates and configures the FastAPI application.

    Returns:
        FastAPI: Configured application instance.
    """
    application = FastAPI(
        title=PROJECT_NAME,
        version=PROJECT_VERSION,
        description=(
            "Modular backend Attack Surface Engineering platform. "
            "Accepts an authorized domain or IP address, performs direct active scanning, "
            "and returns evidence-based structured attack surface data."
        ),
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
        lifespan=lifespan,
    )

    # ─────────────────────────────────────────────
    # CORS Middleware Configuration
    # Allows cross-origin requests from deployed Frontend UI
    # ─────────────────────────────────────────────
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Root health check endpoint for monitoring probes
    @application.get("/health", tags=["System"])
    async def root_health():
        return {
            "status": "healthy",
            "version": PROJECT_VERSION,
            "environment": settings.app_env,
        }

    # ─────────────────────────────────────────────
    # Register all API routes under the /api/v1 prefix
    # ─────────────────────────────────────────────
    application.include_router(api_router, prefix=API_PREFIX)

    # ─────────────────────────────────────────────
    # Global exception handlers
    # These ensure that all unhandled domain errors produce
    # structured JSON responses instead of raw tracebacks.
    # ─────────────────────────────────────────────
    @application.exception_handler(AttackSurfaceEngineError)
    async def handle_domain_error(
        request: Request, exc: AttackSurfaceEngineError
    ) -> JSONResponse:
        """
        Convert any AttackSurfaceEngineError subclass into a structured
        400 JSON error response.

        Internal stack traces are logged but never exposed to the caller.
        """
        logger.warning(
            "Domain error: error_type=%s message=%s",
            exc.error_type,
            exc.message,
        )
        return JSONResponse(
            status_code=400,
            content={
                "status": "failed",
                "error_type": exc.error_type,
                "message": exc.message,
            },
        )

    @application.exception_handler(Exception)
    async def handle_unexpected_error(
        request: Request, exc: Exception
    ) -> JSONResponse:
        """
        Catch-all handler for unexpected exceptions.

        Logs the full error internally. Returns a generic safe message
        to the caller — internal details are never exposed.
        """
        logger.exception("Unexpected internal error: %s", exc)
        return JSONResponse(
            status_code=500,
            content={
                "status": "failed",
                "error_type": "internal_error",
                "message": "An unexpected internal error occurred.",
            },
        )

    return application


# ─────────────────────────────────────────────
# Application instance used by uvicorn
# ─────────────────────────────────────────────
app = create_application()
