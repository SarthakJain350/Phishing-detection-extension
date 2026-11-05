"""Pytest fixtures and configuration."""

from __future__ import annotations

import os
import sys
from collections.abc import Generator
from backend.app.api.v1.scans import get_orchestrator
from backend.app.detection.orchestrator import RealDetectionOrchestrator
from backend.app.schemas.scan import EvidenceItem, ToolStatusDetail
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

# Ensure project root is on sys.path
project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
if project_root not in sys.path:
    sys.path.insert(0, project_root)

from backend.app.db.base import Base
from backend.app.db.session import get_db
from backend.app.main import app
import backend.app.db.models


class UnavailableGemini:
    def analyze_target(self, **kwargs):
        return None, ToolStatusDetail(
            status="unavailable",
            reason_code="test_provider_disabled",
        )


class UnavailableReputation:
    """Test stub: reputation provider not integrated (default test state)."""

    def check_reputation(self, **kwargs):
        return [], ToolStatusDetail(
            status="unavailable",
            reason_code="provider_not_integrated",
        )


class CleanReputation:
    """Test stub: reputation lookup completes with no threats found."""

    def check_reputation(self, **kwargs):
        return [], ToolStatusDetail(status="complete")


class ThreatReputation:
    """Test stub: reputation lookup completes and flags a SOCIAL_ENGINEERING threat."""

    def check_reputation(self, **kwargs):
        evidence = [
            EvidenceItem(
                type="reputation_threat",
                source="reputation",
                severity="high",
                explanation=(
                    "Google Safe Browsing flagged this URL as social engineering / phishing. "
                    "This is a strong signal of malicious intent."
                ),
            )
        ]
        return evidence, ToolStatusDetail(status="complete")


@pytest.fixture(scope="session")
def sqlite_engine():
    engine = create_engine(
        "sqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )

    from sqlalchemy import event

    @event.listens_for(engine, "connect")
    def set_sqlite_pragma(dbapi_connection, connection_record):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    Base.metadata.create_all(bind=engine)
    yield engine
    Base.metadata.drop_all(bind=engine)


@pytest.fixture
def sqlite_session(sqlite_engine) -> Generator[Session, None, None]:
    connection = sqlite_engine.connect()
    transaction = connection.begin()
    SessionLocal = sessionmaker(bind=connection)
    session = SessionLocal()

    yield session

    session.close()
    if transaction.is_active:
        transaction.rollback()
    connection.close()


@pytest.fixture
def client(sqlite_session) -> Generator[TestClient, None, None]:
    def override_get_db():
        yield sqlite_session

    def override_get_orchestrator():
        return RealDetectionOrchestrator(
            gemini=UnavailableGemini(),
            reputation=UnavailableReputation(),
        )

    app.dependency_overrides[get_db] = override_get_db
    app.dependency_overrides[get_orchestrator] = override_get_orchestrator

    try:
        with TestClient(app) as test_client:
            yield test_client
    finally:
        app.dependency_overrides.clear()