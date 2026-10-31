"""Pytest fixtures and configuration."""

from __future__ import annotations

import os
import sys
from collections.abc import Generator

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
import backend.app.db.models  # Ensure models are loaded into Base.metadata


@pytest.fixture(scope="session")
def sqlite_engine():
    """Create an in-memory SQLite engine with StaticPool for zero-dependency testing."""
    engine = create_engine(
        "sqlite:///:memory:",
        echo=False,
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    # Enable SQLite foreign keys and check constraints
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
    """Provide a transactional database session rolled back after each test."""
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
    """Provide a FastAPI TestClient with the database session overridden to in-memory SQLite."""
    def override_get_db():
        yield sqlite_session

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as test_client:
        yield test_client
    app.dependency_overrides.clear()
