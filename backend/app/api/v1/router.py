"""API v1 router assembly."""

from __future__ import annotations

from fastapi import APIRouter

from backend.app.api.v1.health import router as health_router
from backend.app.api.v1.scans import router as scans_router

api_v1_router = APIRouter(prefix="/api/v1")

api_v1_router.include_router(health_router)
api_v1_router.include_router(scans_router)
