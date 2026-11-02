"""Database engine and session management."""

from __future__ import annotations

import logging
from collections.abc import Generator

from fastapi import HTTPException, status
from sqlalchemy import create_engine
from sqlalchemy.exc import OperationalError, TimeoutError as SATimeoutError
from sqlalchemy.orm import Session, sessionmaker

from backend.app.core.config import settings

logger = logging.getLogger("phishing_detector")

# ---------------------------------------------------------------------------
# psycopg3 / psycopg driver-level connect_timeout
# ---------------------------------------------------------------------------
# SQLAlchemy passes connect_args directly to the underlying DBAPI driver.
# For psycopg (v3), "connect_timeout" is a libpq parameter (seconds).
# Without this, a TCP connect to a dead/unreachable host blocks for the OS
# default (often 60-130 s) and the entire request thread hangs.
# ---------------------------------------------------------------------------
_CONNECT_ARGS: dict = {}
if settings.DATABASE_URL.startswith("postgresql"):
    _CONNECT_ARGS["connect_timeout"] = 5  # seconds to establish TCP connection

engine = create_engine(
    settings.DATABASE_URL,
    echo=False,
    # Test connections before handing them to the application.
    # If the connection is dead, SQLAlchemy checks out a new one from the pool
    # rather than returning a stale socket that will block on the first query.
    pool_pre_ping=True,
    # Maximum number of persistent connections kept open.
    pool_size=5,
    # Allow up to this many overflow connections beyond pool_size under load.
    max_overflow=10,
    # Seconds to wait for a connection slot from the pool before giving up.
    # Without this, the request thread can block indefinitely if all
    # connections are busy (e.g., due to a long-running lock).
    pool_timeout=10,
    # Recycle connections older than this many seconds to prevent stale-socket
    # issues after the database server restarts.
    pool_recycle=1800,
    # Forward driver-level timeout to the underlying DBAPI.
    connect_args=_CONNECT_ARGS,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


def get_db() -> Generator[Session, None, None]:
    """Dependency generator for FastAPI routes.

    Converts database connectivity errors into a structured HTTP 503 response
    so callers receive a meaningful error instead of a silent timeout.
    """
    try:
        db = SessionLocal()
    except (OperationalError, SATimeoutError, Exception) as exc:
        logger.error("Cannot acquire database connection: %s", exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is temporarily unavailable. Please try again shortly.",
        ) from exc
    try:
        yield db
    finally:
        db.close()
