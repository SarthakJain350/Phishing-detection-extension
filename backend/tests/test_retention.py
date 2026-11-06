
from datetime import datetime, timedelta, timezone

import pytest

from backend.app.core.config import settings
from backend.app.db.models import ScanRecord
from backend.app.services.retention import cleanup_expired_scans


def create_scan(db, created_at):
    record = ScanRecord(
        target_type="website",
        target_reference="retention-test.com",
        classification="likely_legitimate",
        risk_score=10,
        evidence=[],
        tool_statuses={},
        analysis_status="complete",
        source="manual_website",
        created_at=created_at,
    )
    db.add(record)
    db.commit()
    return record


def test_cleanup_deletes_expired_scans(sqlite_session):
    now = datetime.now(timezone.utc)
    retention_days = settings.SCAN_RETENTION_DAYS

    create_scan(
        sqlite_session,
        now - timedelta(days=retention_days + 2),
    )
    create_scan(
        sqlite_session,
        now - timedelta(days=retention_days + 5),
    )

    deleted = cleanup_expired_scans(sqlite_session, now=now)

    assert deleted == 2
    assert sqlite_session.query(ScanRecord).count() == 0


def test_cleanup_preserves_recent_scans(sqlite_session):
    now = datetime.now(timezone.utc)
    retention_days = settings.SCAN_RETENTION_DAYS

    create_scan(
        sqlite_session,
        now - timedelta(days=retention_days - 1),
    )

    deleted = cleanup_expired_scans(sqlite_session, now=now)

    assert deleted == 0
    assert sqlite_session.query(ScanRecord).count() == 1


def test_cleanup_preserves_record_at_exact_cutoff(sqlite_session):
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(days=settings.SCAN_RETENTION_DAYS)

    create_scan(sqlite_session, cutoff)

    deleted = cleanup_expired_scans(sqlite_session, now=now)

    assert deleted == 0
    assert sqlite_session.query(ScanRecord).count() == 1


def test_cleanup_rejects_naive_datetime(sqlite_session):
    naive_now = datetime.now()

    with pytest.raises(ValueError, match="timezone-aware"):
        cleanup_expired_scans(sqlite_session, now=naive_now)
