"""Pydantic schemas for website and email phishing detection scans."""

from __future__ import annotations

import re
import urllib.parse
import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator


class WebsiteScanRequest(BaseModel):
    """Payload submitted for scanning a website."""

    model_config = ConfigDict(extra="forbid")

    url: str = Field(
        ...,
        min_length=1,
        max_length=2048,
        description="Target website URL (http or https only).",
    )
    page_title: str | None = Field(
        None,
        max_length=256,
        description="Optional visible page title.",
    )
    visible_text: str | None = Field(
        None,
        max_length=2000,
        description="Bounded visible text excerpt extracted from page.",
    )
    source: Literal["manual_website", "auto_website"] = Field(
        default="manual_website",
        description="Origin of scan trigger.",
    )

    @field_validator("url")
    @classmethod
    def validate_website_url(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("URL cannot be empty or whitespace.")
        if len(cleaned) > 2048:
            raise ValueError("URL exceeds maximum length of 2048 characters.")

        # Ensure scheme is strictly http or https
        parsed = urllib.parse.urlsplit(cleaned)
        scheme = parsed.scheme.lower()
        if scheme not in {"http", "https"}:
            raise ValueError(f"Invalid URL scheme '{scheme}'. Only http and https schemes are permitted.")

        host = parsed.hostname
        if not host:
            raise ValueError("URL must include a valid host.")

        return cleaned


class EmailScanRequest(BaseModel):
    """Payload submitted for scanning an open Gmail message."""

    model_config = ConfigDict(extra="forbid")

    sender: str | None = Field(
        None,
        max_length=256,
        description="Sender information or email domain.",
    )
    subject: str | None = Field(
        None,
        max_length=256,
        description="Subject line of email.",
    )
    body_text: str | None = Field(
        None,
        max_length=3000,
        description="Bounded plain text excerpt of message body.",
    )
    links: list[str] = Field(
        default_factory=list,
        max_length=10,
        description="Capped list of extracted link URLs (up to 10).",
    )
    source: Literal["gmail"] = Field(
        default="gmail",
        description="Source of email scan.",
    )

    @field_validator("links")
    @classmethod
    def validate_links(cls, links: list[str]) -> list[str]:
        if len(links) > 10:
            raise ValueError("Maximum of 10 links allowed per email scan.")
        for link in links:
            cleaned = link.strip()
            if len(cleaned) > 2048:
                raise ValueError("Link URL exceeds maximum length of 2048 characters.")
            parsed = urllib.parse.urlsplit(cleaned)
            if parsed.scheme.lower() not in {"http", "https"}:
                raise ValueError(f"Invalid link URL scheme '{parsed.scheme}'. Only http and https are permitted.")
        return links


class EvidenceItem(BaseModel):
    """Single concrete evidence finding explaining a classification."""

    model_config = ConfigDict(extra="forbid")

    type: str = Field(..., description="Machine-readable evidence identifier (e.g. misleading_subdomain).")
    source: str = Field(..., description="Tool producing evidence: heuristics, reputation, llm.")
    severity: Literal["low", "medium", "high"] = Field(..., description="Severity level of the evidence signal.")
    explanation: str = Field(..., description="Human-readable plain language explanation.")


class ToolStatusDetail(BaseModel):
    """Status summary for an individual detection tool."""

    model_config = ConfigDict(extra="forbid")

    status: Literal["complete", "partial", "unavailable", "timeout", "error"]
    reason_code: str | None = None


class ToolStatuses(BaseModel):
    """Per-tool status breakdown."""

    model_config = ConfigDict(extra="forbid")

    heuristics: ToolStatusDetail
    reputation: ToolStatusDetail
    llm: ToolStatusDetail


class ScanResponse(BaseModel):
    """Standardized response schema returned for website and email scans."""

    model_config = ConfigDict(from_attributes=True, extra="forbid")

    scan_id: uuid.UUID
    target_type: Literal["website", "email"]
    target_reference: str
    classification: Literal["phishing", "suspicious", "likely_legitimate"] | None = None
    risk_score: int | None = Field(None, ge=0, le=100)
    reasons: list[str]
    evidence: list[EvidenceItem]
    tool_statuses: ToolStatuses
    analysis_status: Literal["complete", "partial", "unavailable"]
    source: str
    created_at: datetime


class ScanListResponse(BaseModel):
    """Paginated list of scan summaries."""

    model_config = ConfigDict(extra="forbid")

    items: list[ScanResponse]
    total: int
    limit: int
    offset: int
