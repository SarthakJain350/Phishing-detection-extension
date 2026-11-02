"""Scan endpoints for website and email phishing detection."""

from __future__ import annotations

import logging
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.exc import OperationalError, TimeoutError as SATimeoutError
from sqlalchemy.orm import Session

from backend.app.core.domain import clean_url_or_hostname, normalize_target_reference
from backend.app.db.repository import ScanRepository
from backend.app.db.session import get_db
from backend.app.detection.orchestrator import (
    BaseDetectionOrchestrator,
    RealDetectionOrchestrator,
)
from backend.app.schemas.scan import (
    EmailScanRequest,
    EvidenceItem,
    ScanListResponse,
    ScanResponse,
    ToolStatuses,
    WebsiteScanRequest,
)

logger = logging.getLogger("phishing_detector")

router = APIRouter(prefix="/scans", tags=["Scans"])

# Default orchestrator instance (can be overridden in tests or future phases)
_default_orchestrator: BaseDetectionOrchestrator = RealDetectionOrchestrator()


def get_orchestrator() -> BaseDetectionOrchestrator:
    """Dependency provider for detection orchestrator."""
    return _default_orchestrator


def _build_scan_response(record, reasons: list[str] | None = None) -> ScanResponse:
    """Map a database ScanRecord and optional reasons into a ScanResponse."""
    evidence_items = [
        EvidenceItem(
            type=item.get("type", "unknown"),
            source=item.get("source", "heuristics"),
            severity=item.get("severity", "low"),
            explanation=item.get("explanation", ""),
        )
        for item in (record.evidence or [])
    ]

    # Reconstruct human-readable reasons from evidence explanations if not provided
    if reasons is None:
        reasons = [item.explanation for item in evidence_items if item.explanation]
        if not reasons:
            if record.classification == "phishing":
                reasons = ["High risk indicators detected matching known deceptive patterns."]
            elif record.classification == "suspicious":
                reasons = ["Moderate risk signals observed requiring caution."]
            elif record.analysis_status == "unavailable":
                reasons = ["Analysis could not be completed; detection providers are unavailable."]
            else:
                reasons = [
                    "No strong phishing signals detected across available checks. Advisory assessment only; safety is not guaranteed."
                ]

    tool_statuses = ToolStatuses.model_validate(
        record.tool_statuses
        or {
            "heuristics": {"status": "unavailable", "reason_code": "status_missing"},
            "reputation": {
                "status": "unavailable",
                "reason_code": "status_missing",
            },
            "llm": {"status": "unavailable", "reason_code": "status_missing"},
        }
    )

    return ScanResponse(
        scan_id=record.id,
        target_type=record.target_type,
        target_reference=record.target_reference,
        classification=record.classification,
        risk_score=record.risk_score,
        reasons=reasons,
        evidence=evidence_items,
        tool_statuses=tool_statuses,
        analysis_status=record.analysis_status,
        source=record.source,
        created_at=record.created_at,
    )


@router.post("/website", response_model=ScanResponse, summary="Scan a website URL")
def scan_website(
    payload: WebsiteScanRequest,
    db: Session = Depends(get_db),
    orchestrator: BaseDetectionOrchestrator = Depends(get_orchestrator),
) -> ScanResponse:
    """Validate submitted website URL, normalize domain, analyze, and persist result."""
    try:
        # Strictly extract and normalize only the domain/hostname for privacy
        target_reference = normalize_target_reference(payload.url)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid website URL or host: {exc}",
        ) from exc

    # Run orchestrator
    result = orchestrator.analyze_website(
        url=payload.url,
        target_reference=target_reference,
        page_title=payload.page_title,
        visible_text=payload.visible_text,
    )

    # Persist record (never persists raw full URL or visible text)
    try:
        record = ScanRepository.create_scan(
            db,
            target_type="website",
            target_reference=target_reference,
            classification=result.classification,
            risk_score=result.risk_score,
            evidence=[e.model_dump() for e in result.evidence],
            tool_statuses=result.tool_statuses.model_dump(),
            analysis_status=result.analysis_status,
            source=payload.source,
        )
    except (OperationalError, SATimeoutError, Exception) as exc:
        logger.error("Database write failed for website scan (target=%s): %s", target_reference, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is temporarily unavailable. The scan result could not be saved. Please try again shortly.",
        ) from exc

    return _build_scan_response(record, reasons=result.reasons)


@router.post("/email", response_model=ScanResponse, summary="Scan extracted email indicators")
def scan_email(
    payload: EmailScanRequest,
    db: Session = Depends(get_db),
    orchestrator: BaseDetectionOrchestrator = Depends(get_orchestrator),
) -> ScanResponse:
    """Validate submitted email indicators, extract primary domain reference, analyze, and persist."""
    # Determine non-sensitive primary target reference from sender domain or first link
    primary_domain = "email-message"
    if payload.sender and "@" in payload.sender:
        try:
            sender_domain = payload.sender.split("@", 1)[1]
            primary_domain = clean_url_or_hostname(sender_domain)
        except ValueError:
            primary_domain = "email-message"
    elif payload.links:
        try:
            primary_domain = normalize_target_reference(payload.links[0])
        except ValueError:
            primary_domain = "email-message"

    result = orchestrator.analyze_email(
        sender=payload.sender,
        subject=payload.subject,
        body_text=payload.body_text,
        links=payload.links,
        primary_domain=primary_domain,
    )

    # Persist record (never persists full message body or full link paths)
    try:
        record = ScanRepository.create_scan(
            db,
            target_type="email",
            target_reference=primary_domain,
            classification=result.classification,
            risk_score=result.risk_score,
            evidence=[e.model_dump() for e in result.evidence],
            tool_statuses=result.tool_statuses.model_dump(),
            analysis_status=result.analysis_status,
            source=payload.source,
        )
    except (OperationalError, SATimeoutError, Exception) as exc:
        logger.error("Database write failed for email scan (target=%s): %s", primary_domain, exc)
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Database is temporarily unavailable. The scan result could not be saved. Please try again shortly.",
        ) from exc

    return _build_scan_response(record, reasons=result.reasons)


@router.get("", response_model=ScanListResponse, summary="List recent scan history")
def list_scans(
    limit: Annotated[int, Query(ge=1, le=100, description="Page limit (max 100)")] = 20,
    offset: Annotated[int, Query(ge=0, description="Offset cursor")] = 0,
    db: Session = Depends(get_db),
) -> ScanListResponse:
    """Retrieve paginated scan history ordered newest first."""
    items, total = ScanRepository.list_scans(db, limit=limit, offset=offset)
    response_items = [_build_scan_response(item) for item in items]

    return ScanListResponse(
        items=response_items,
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get("/{scan_id}", response_model=ScanResponse, summary="Retrieve a stored scan by UUID")
def get_scan(
    scan_id: uuid.UUID,
    db: Session = Depends(get_db),
) -> ScanResponse:
    """Retrieve a single stored scan result by its UUID."""
    record = ScanRepository.get_scan_by_id(db, scan_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record with ID '{scan_id}' not found.",
        )
    return _build_scan_response(record)
