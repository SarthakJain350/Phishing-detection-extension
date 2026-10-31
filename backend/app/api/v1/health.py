"""Health and readiness check endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.db.session import get_db

router = APIRouter(prefix="/health", tags=["Health"])


@router.get("", summary="Liveness check")
def health_check() -> dict[str, str]:
    """Basic liveness check verifying the HTTP process is running."""
    return {"status": "ok"}


@router.get("/ready", summary="Readiness check")
def readiness_check(db: Session = Depends(get_db)) -> dict[str, str]:
    """Readiness probe verifying database connectivity."""
    try:
        db.execute(text("SELECT 1"))
        return {
            "status": "ready",
            "database": "connected",
        }
    except Exception as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Database readiness check failed: {exc}",
        ) from exc
