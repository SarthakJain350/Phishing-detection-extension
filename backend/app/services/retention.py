
"""Scheduled scan-history retention cleanup service."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.orm import Session

from backend.app.core.config import settings
from backend.app.db.repository import ScanRepository


def cleanup_expired_scans(
    db: Session,
    *,
    now: datetime | None = None,
) -> int:
    """Delete scan records older than the configured retention period.

    Args:
        db: Active database session.
        now: Optional timezone-aware reference time, useful for testing.

    Returns:
        Number of expired scan records deleted.
    """
    current_time = now or datetime.now(timezone.utc)

    if current_time.tzinfo is None or current_time.utcoffset() is None:
        raise ValueError("The reference time must be timezone-aware.")

    cutoff = current_time - timedelta(days=settings.SCAN_RETENTION_DAYS)

    return ScanRepository.delete_expired_scans(
        db,
        older_than=cutoff,
    )
