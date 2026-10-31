"""Integration tests executing against a live PostgreSQL 16 instance.

REQUIRES DOCKER / POSTGRESQL:
    These tests require a running PostgreSQL instance (e.g. started via `docker compose up -d db`).
    If PostgreSQL is unreachable at the configured DATABASE_URL, these tests are skipped
    with an explanatory message, clearly distinguishing them from local unit tests.
"""

from __future__ import annotations

import socket
import urllib.parse
import uuid
import pytest
from sqlalchemy import create_engine, select, text
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import sessionmaker

from backend.app.core.config import settings
from backend.app.db.base import Base
from backend.app.db.models import ScanRecord


def is_postgres_reachable() -> bool:
    """Check if the configured PostgreSQL host and port are accepting TCP connections."""
    try:
        parsed = urllib.parse.urlsplit(settings.DATABASE_URL.replace("+psycopg", ""))
        host = parsed.hostname or "localhost"
        port = parsed.port or 5432
        with socket.create_connection((host, port), timeout=1.0):
            return True
    except (OSError, ValueError):
        return False


@pytest.fixture(scope="module")
def postgres_session():
    """Fixture that connects to live PostgreSQL instance.

    Skips if database is unreachable.
    """
    if not is_postgres_reachable():
        pytest.skip(
            f"Live PostgreSQL instance is unreachable at {settings.DATABASE_URL}. "
            "To run these tests: start Docker Desktop and execute 'docker compose up -d db'."
        )

    try:
        engine = create_engine(settings.DATABASE_URL, pool_pre_ping=True)
        # Verify connection
        with engine.connect() as conn:
            conn.execute(text("SELECT 1"))

        # Create schema tables
        Base.metadata.create_all(bind=engine)
        Session = sessionmaker(bind=engine)
        session = Session()

        yield session

        session.close()
        # Clean up created records
        with engine.connect() as conn:
            conn.execute(text("DELETE FROM scans WHERE target_reference LIKE 'pg-test-%'"))
            conn.commit()
    except Exception as exc:
        pytest.skip(f"Could not initialize PostgreSQL session: {exc}")


@pytest.mark.postgres_integration
class TestLivePostgresIntegration:
    """Live PostgreSQL 16 database verification tests."""

    def test_live_postgres_insert_and_jsonb_query(self, postgres_session):
        test_id = uuid.uuid4()
        scan = ScanRecord(
            id=test_id,
            target_type="website",
            target_reference="pg-test-paypal-verification.com",
            classification="phishing",
            risk_score=92,
            evidence=[
                {
                    "type": "misleading_subdomain",
                    "source": "heuristics",
                    "severity": "high",
                    "explanation": "Simulated live PG test.",
                }
            ],
            tool_statuses={"heuristics": {"status": "complete"}},
            analysis_status="complete",
            source="manual_website",
        )
        postgres_session.add(scan)
        postgres_session.commit()

        # Query back using SQLAlchemy select
        stmt = select(ScanRecord).where(ScanRecord.id == test_id)
        result = postgres_session.scalar(stmt)
        assert result is not None
        assert result.target_reference == "pg-test-paypal-verification.com"
        assert result.risk_score == 92
        assert result.evidence[0]["type"] == "misleading_subdomain"

    def test_live_postgres_check_constraint_enforcement(self, postgres_session):
        """Verify PostgreSQL enforces the check constraint ck_scans_risk_score_range."""
        invalid_scan = ScanRecord(
            id=uuid.uuid4(),
            target_type="website",
            target_reference="pg-test-invalid-score.com",
            classification="phishing",
            risk_score=105,  # Violates 0 <= risk_score <= 100
            evidence=[],
            tool_statuses={},
            analysis_status="complete",
            source="manual_website",
        )
        postgres_session.add(invalid_scan)
        with pytest.raises(IntegrityError):
            postgres_session.commit()
        postgres_session.rollback()
