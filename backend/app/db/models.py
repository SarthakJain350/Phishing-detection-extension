"""SQLAlchemy models for Phishing Attack Detector."""

from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    DateTime,
    Index,
    JSON,
    SmallInteger,
    String,
    Uuid,
    func,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from backend.app.db.base import Base

# Universal JSON type that uses PostgreSQL JSONB when running on PostgreSQL,
# and falls back to standard JSON on SQLite (for zero-dependency unit tests).
JSON_TYPE = JSON().with_variant(JSONB, "postgresql")


class ScanRecord(Base):
    """Represents a single scan attempt for a website or email target."""

    __tablename__ = "scans"

    # Primary key: native UUID on PostgreSQL, string representation on SQLite
    id: Mapped[uuid.UUID] = mapped_column(
        Uuid(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )

    # Scan target type: website or email
    target_type: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )

    # Normalized hostname/domain only (e.g. 'login.example.com' or '192.168.1.1')
    # Full URLs, query parameters, auth tokens, and page content are strictly forbidden.
    target_reference: Mapped[str] = mapped_column(
        String(255),
        nullable=False,
    )

    # Classification label: phishing, suspicious, likely_legitimate.
    # Explicitly nullable: when analysis_status is 'unavailable', classification must be NULL.
    classification: Mapped[str | None] = mapped_column(
        String(32),
        nullable=True,
    )

    # Risk score: 0 to 100 risk indicator.
    # Explicitly nullable: when analysis_status is 'unavailable', risk_score must be NULL.
    risk_score: Mapped[int | None] = mapped_column(
        SmallInteger,
        nullable=True,
    )

    # Structured array of evidence items
    # Example: [{"type": "misleading_subdomain", "source": "heuristics", "severity": "high", "explanation": "..."}]
    evidence: Mapped[list[dict[str, Any]]] = mapped_column(
        JSON_TYPE,
        nullable=False,
        default=list,
    )

    # Per-tool status summaries
    # Example: {"heuristics": {"status": "complete"}, "reputation": {"status": "unavailable"}}
    tool_statuses: Mapped[dict[str, Any]] = mapped_column(
        JSON_TYPE,
        nullable=False,
        default=dict,
    )

    # Analysis completeness: complete, partial, unavailable
    analysis_status: Mapped[str] = mapped_column(
        String(16),
        nullable=False,
    )

    # Scan source: manual_website, auto_website, gmail
    source: Mapped[str] = mapped_column(
        String(32),
        nullable=False,
    )

    # Creation timestamp with UTC timezone
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        server_default=func.now(),
    )

    # Table constraints and indexes
    __table_args__ = (
        # Constraint: Risk score must be between 0 and 100 if present
        CheckConstraint(
            "(risk_score IS NULL) OR (risk_score >= 0 AND risk_score <= 100)",
            name="ck_scans_risk_score_range",
        ),
        # Constraint: Target type must be known value
        CheckConstraint(
            "target_type IN ('website', 'email')",
            name="ck_scans_target_type",
        ),
        # Constraint: Analysis status must be known value
        CheckConstraint(
            "analysis_status IN ('complete', 'partial', 'unavailable')",
            name="ck_scans_analysis_status",
        ),
        # Index: History queries ordered by newest first
        Index("ix_scans_created_at", created_at.desc()),
        # Index: Filter by target domain over time
        Index("ix_scans_target_created_at", target_reference, created_at.desc()),
        # Index: Filter by classification over time
        Index("ix_scans_classification_created_at", classification, created_at.desc()),
    )

    def __repr__(self) -> str:
        return (
            f"<ScanRecord(id={self.id}, target_type='{self.target_type}', "
            f"target='{self.target_reference}', classification='{self.classification}', "
            f"score={self.risk_score}, status='{self.analysis_status}')>"
        )
