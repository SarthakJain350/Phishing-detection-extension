"""FastAPI application entry point for Phishing Attack Detector."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.api.v1.router import api_v1_router
from backend.app.api.v1.health import router as health_router
from backend.app.core.config import settings
from backend.app.services.retention import retention_scheduler_worker

logger = logging.getLogger("phishing_detector")


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Application startup and shutdown events."""
    logger.info("Phishing Attack Detector API starting up...")

    # Start retention cleanup scheduler background task
    retention_stop_event = asyncio.Event()
    retention_task = asyncio.create_task(
        retention_scheduler_worker(stop_event=retention_stop_event),
        name="retention-scheduler",
    )

    try:
        yield
    finally:
        logger.info("Phishing Attack Detector API shutting down...")
        # Signal stop and await worker task completion naturally
        retention_stop_event.set()
        try:
            await retention_task
        except asyncio.CancelledError:
            pass
        except Exception as exc:
            logger.error("Error during retention task shutdown: %s", exc)


app = FastAPI(
    title="Phishing Attack Detector API",
    description="Backend API for Chrome extension phishing detection, evidence explanation, and scan history.",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# ------------------------------------------------------------------------------
# Security: CORS Middleware
# ------------------------------------------------------------------------------
# Wildcard 'chrome-extension://*' is strictly forbidden.
# Uses explicit origins from application settings.
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)


# ------------------------------------------------------------------------------
# Standardized Error Handlers
# ------------------------------------------------------------------------------
@app.exception_handler(RequestValidationError)
async def validation_exception_handler(
    request: Request,
    exc: RequestValidationError,
) -> JSONResponse:
    """Standardize all invalid-request payload errors to HTTP 400."""
    error_messages = []
    for err in exc.errors():
        field_loc = " -> ".join(str(loc) for loc in err.get("loc", []))
        msg = err.get("msg", "Invalid value")
        error_messages.append(f"{field_loc}: {msg}")

    return JSONResponse(
        status_code=status.HTTP_400_BAD_REQUEST,
        content={
            "error": {
                "code": "VALIDATION_ERROR",
                "message": "; ".join(error_messages) or "Request validation failed.",
                "request_id": None,
            }
        },
    )


@app.exception_handler(HTTPException)
async def http_exception_handler(
    request: Request,
    exc: HTTPException,
) -> JSONResponse:
    """Format HTTPExceptions into standard structured error shape."""
    code_map = {
        status.HTTP_400_BAD_REQUEST: "BAD_REQUEST",
        status.HTTP_404_NOT_FOUND: "NOT_FOUND",
        status.HTTP_503_SERVICE_UNAVAILABLE: "SERVICE_UNAVAILABLE",
    }
    code = code_map.get(exc.status_code, f"HTTP_{exc.status_code}")

    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": {
                "code": code,
                "message": str(exc.detail),
                "request_id": None,
            }
        },
    )


@app.exception_handler(Exception)
async def generic_exception_handler(
    request: Request,
    exc: Exception,
) -> JSONResponse:
    """Catch unhandled errors and return 500 without leaking stack traces or internal secrets."""
    logger.error("Unhandled server error: %s", exc, exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": {
                "code": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected server error occurred.",
                "request_id": None,
            }
        },
    )


# ------------------------------------------------------------------------------
# Include API Routers
# ------------------------------------------------------------------------------
app.include_router(api_v1_router)
# Expose health endpoints at root level for extension compatibility (alias)
app.include_router(health_router)
