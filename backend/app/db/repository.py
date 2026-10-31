"""Repository layer for persisting and retrieving ScanRecord entities."""

from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from backend.app.db.models import ScanRecord


class ScanRepository:
    """Encapsulates database operations for scan records.

    PRIVACY GUARANTEE:
    This repository accepts only the normalized target_reference (hostname/domain).
    Full URLs, query parameters, auth tokens, page text, and email bodies are
    never accepted or written to the database.
    """

    @staticmethod
    def create_scan(
        db: Session,
        *,
        target_type: str,
        target_reference: str,
        classification: str | None,
        risk_score: int | None,
        evidence: list[dict[str, Any]],
        tool_statuses: dict[str, Any],
        analysis_status: str,
        source: str,
        scan_id: uuid.UUID | None = None,
    ) -> ScanRecord:
        """Persist a new scan record and return the created instance."""
        record = ScanRecord(
            id=scan_id or uuid.uuid4(),
            target_type=target_type,
            target_reference=target_reference,
            classification=classification,
            risk_score=risk_score,
            evidence=evidence,
            tool_statuses=tool_statuses,
            analysis_status=analysis_status,
            source=source,
        )
        db.add(record)
        db.commit()
        db.refresh(record)
        return record

    @staticmethod
    def get_scan_by_id(db: Session, scan_id: uuid.UUID) -> ScanRecord | None:
        """Retrieve a single scan record by its UUID."""
        stmt = select(ScanRecord).where(ScanRecord.id == scan_id)
        return db.scalar(stmt)

    @staticmethod
    def list_scans(
        db: Session,
        *,
        limit: int = 20,
        offset: int = 0,
    ) -> tuple[list[ScanRecord], int]:
        """Retrieve a paginated list of scan records ordered newest first.

        Returns:
            (items, total_count)
        """
        # Count total
        count_stmt = select(func.count(ScanRecord.id))
        total = db.scalar(count_stmt) or 0

        # Query items
        stmt = (
            select(ScanRecord)
            .order_by(ScanRecord.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        items = list(db.scalars(stmt).all())
        return items, total
