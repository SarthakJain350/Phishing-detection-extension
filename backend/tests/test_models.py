"""Unit tests for SQLAlchemy ScanRecord model and database constraints.

These tests run locally in-memory without requiring Docker or a running PostgreSQL instance.
"""

from __future__ import annotations

import uuid
import pytest
from sqlalchemy import inspect
from sqlalchemy.exc import IntegrityError

from backend.app.db.models import ScanRecord


class TestScanRecordModelStructure:
    """Verify table schema, column definitions, check constraints, and indexes."""

    def test_table_name_and_columns(self):
        mapper = inspect(ScanRecord)
        assert mapper.persist_selectable.name == "scans"

        columns = {c.name for c in mapper.columns}
        expected_columns = {
            "id",
            "target_type",
            "target_reference",
            "classification",
            "risk_score",
            "evidence",
            "tool_statuses",
            "analysis_status",
            "source",
            "created_at",
        }
        assert expected_columns.issubset(columns)

    def test_check_constraints_defined(self):
        table = ScanRecord.__table__
        constraint_names = {c.name for c in table.constraints if c.name}
        assert "ck_scans_risk_score_range" in constraint_names
        assert "ck_scans_target_type" in constraint_names
        assert "ck_scans_analysis_status" in constraint_names

    def test_indexes_defined(self):
        table = ScanRecord.__table__
        index_names = {idx.name for idx in table.indexes}
        assert "ix_scans_created_at" in index_names
        assert "ix_scans_target_created_at" in index_names
        assert "ix_scans_classification_created_at" in index_names


class TestScanRecordDatabaseOperations:
    """Test model insertion and constraint validation in-memory."""

    def test_create_complete_scan_record(self, sqlite_session):
        scan = ScanRecord(
            id=uuid.uuid4(),
            target_type="website",
            target_reference="login.paypal.com",
            classification="phishing",
            risk_score=85,
            evidence=[
                {
                    "type": "misleading_subdomain",
                    "source": "heuristics",
                    "severity": "high",
                    "explanation": "Lookalike subdomain pattern detected.",
                }
            ],
            tool_statuses={"heuristics": {"status": "complete"}},
            analysis_status="complete",
            source="manual_website",
        )
        sqlite_session.add(scan)
        sqlite_session.commit()

        # Query back
        retrieved = sqlite_session.query(ScanRecord).filter_by(id=scan.id).first()
        assert retrieved is not None
        assert retrieved.target_reference == "login.paypal.com"
        assert retrieved.risk_score == 85
        assert retrieved.classification == "phishing"
        assert len(retrieved.evidence) == 1
        assert retrieved.created_at is not None

    def test_create_unavailable_scan_record_nullable_fields(self, sqlite_session):
        """Verify that classification and risk_score are successfully NULL

        when analysis_status is 'unavailable'.
        """
        scan = ScanRecord(
            id=uuid.uuid4(),
            target_type="email",
            target_reference="attacker-domain.xyz",
            classification=None,  # Nullable
            risk_score=None,  # Nullable
            evidence=[],
            tool_statuses={"heuristics": {"status": "unavailable"}},
            analysis_status="unavailable",
            source="gmail",
        )
        sqlite_session.add(scan)
        sqlite_session.commit()

        retrieved = sqlite_session.query(ScanRecord).filter_by(id=scan.id).first()
        assert retrieved is not None
        assert retrieved.classification is None
        assert retrieved.risk_score is None
        assert retrieved.analysis_status == "unavailable"

    def test_check_constraint_rejects_out_of_bounds_score(self, sqlite_session):
        """Verify that score > 100 or < 0 violates the check constraint."""
        scan_high = ScanRecord(
            id=uuid.uuid4(),
            target_type="website",
            target_reference="example.com",
            classification="phishing",
            risk_score=150,  # Invalid
            evidence=[],
            tool_statuses={},
            analysis_status="complete",
            source="manual_website",
        )
        sqlite_session.add(scan_high)
        with pytest.raises(IntegrityError):
            sqlite_session.commit()
        sqlite_session.rollback()

        scan_negative = ScanRecord(
            id=uuid.uuid4(),
            target_type="website",
            target_reference="example.com",
            classification="phishing",
            risk_score=-5,  # Invalid
            evidence=[],
            tool_statuses={},
            analysis_status="complete",
            source="manual_website",
        )
        sqlite_session.add(scan_negative)
        with pytest.raises(IntegrityError):
            sqlite_session.commit()
        sqlite_session.rollback()

    def test_check_constraint_rejects_invalid_target_type(self, sqlite_session):
        """Verify that unsupported target types violate the check constraint."""
        scan_invalid = ScanRecord(
            id=uuid.uuid4(),
            target_type="sms",  # Invalid type
            target_reference="example.com",
            classification="phishing",
            risk_score=50,
            evidence=[],
            tool_statuses={},
            analysis_status="complete",
            source="manual_website",
        )
        sqlite_session.add(scan_invalid)
        with pytest.raises(IntegrityError):
            sqlite_session.commit()
        sqlite_session.rollback()
