"""Detection orchestration interface and deterministic mock implementation.

IMPORTANT NOTICE:
The MockDetectionOrchestrator provides deterministic fixture results for Phase 1
integration testing only. It does not perform actual security analysis or real
phishing detection.
"""

from __future__ import annotations

import abc
from dataclasses import dataclass
from typing import Any

from backend.app.schemas.scan import (
    EvidenceItem,
    ToolStatusDetail,
    ToolStatuses,
)


@dataclass
class DetectionResult:
    """Internal outcome produced by a detection orchestrator."""

    classification: str | None
    risk_score: int | None
    reasons: list[str]
    evidence: list[EvidenceItem]
    tool_statuses: ToolStatuses
    analysis_status: str


class BaseDetectionOrchestrator(abc.ABC):
    """Abstract interface for detection orchestrators."""

    @abc.abstractmethod
    def analyze_website(
        self,
        *,
        url: str,
        target_reference: str,
        page_title: str | None = None,
        visible_text: str | None = None,
    ) -> DetectionResult:
        """Run analysis on a website target."""
        raise NotImplementedError

    @abc.abstractmethod
    def analyze_email(
        self,
        *,
        sender: str | None = None,
        subject: str | None = None,
        body_text: str | None = None,
        links: list[str] | None = None,
        primary_domain: str = "email-scan",
    ) -> DetectionResult:
        """Run analysis on an email target."""
        raise NotImplementedError


class MockDetectionOrchestrator(BaseDetectionOrchestrator):
    """Deterministic mock orchestrator returning fixture data for Phase 1 vertical slice."""

    def _determine_mock_outcome(self, signal_text: str) -> DetectionResult:
        lowered = signal_text.lower()

        # Outcome 1: High risk / Phishing
        if "phish" in lowered or "danger" in lowered:
            return DetectionResult(
                classification="phishing",
                risk_score=88,
                reasons=[
                    "Strong phishing indicators detected matching known deceptive patterns.",
                    "Target domain exhibits high risk characteristics commonly associated with credential harvesting.",
                ],
                evidence=[
                    EvidenceItem(
                        type="known_pattern",
                        source="heuristics",
                        severity="high",
                        explanation="Target structure matches known deceptive patterns (mock signal).",
                    ),
                    EvidenceItem(
                        type="domain_reputation",
                        source="reputation",
                        severity="high",
                        explanation="Domain flagged in reputation database fixture.",
                    ),
                ],
                tool_statuses=ToolStatuses(
                    heuristics=ToolStatusDetail(status="complete"),
                    reputation=ToolStatusDetail(status="complete"),
                    llm=ToolStatusDetail(status="complete"),
                ),
                analysis_status="complete",
            )

        # Outcome 2: Cautionary / Suspicious
        if "suspicious" in lowered:
            return DetectionResult(
                classification="suspicious",
                risk_score=55,
                reasons=[
                    "Moderate risk signals observed requiring user caution before interacting with links.",
                ],
                evidence=[
                    EvidenceItem(
                        type="unusual_structure",
                        source="heuristics",
                        severity="medium",
                        explanation="Target domain contains unusual structural elements requiring manual verification.",
                    )
                ],
                tool_statuses=ToolStatuses(
                    heuristics=ToolStatusDetail(status="complete"),
                    reputation=ToolStatusDetail(status="complete"),
                    llm=ToolStatusDetail(status="complete"),
                ),
                analysis_status="complete",
            )

        # Outcome 3: Degraded / Unavailable (classification and score are NULL)
        if "unavailable" in lowered:
            return DetectionResult(
                classification=None,
                risk_score=None,
                reasons=[
                    "Analysis could not be completed because external detection services are currently unavailable.",
                ],
                evidence=[],
                tool_statuses=ToolStatuses(
                    heuristics=ToolStatusDetail(status="unavailable", reason_code="service_down"),
                    reputation=ToolStatusDetail(status="unavailable", reason_code="provider_timeout"),
                    llm=ToolStatusDetail(status="unavailable", reason_code="quota_exceeded"),
                ),
                analysis_status="unavailable",
            )

        # Outcome 4: Low risk / Likely Legitimate
        return DetectionResult(
            classification="likely_legitimate",
            risk_score=12,
            reasons=[
                "No strong phishing signals detected across available checks.",
                "This is an advisory assessment and does not constitute a guarantee of safety.",
            ],
            evidence=[],
            tool_statuses=ToolStatuses(
                heuristics=ToolStatusDetail(status="complete"),
                reputation=ToolStatusDetail(status="complete"),
                llm=ToolStatusDetail(status="complete"),
            ),
            analysis_status="complete",
        )

    def analyze_website(
        self,
        *,
        url: str,
        target_reference: str,
        page_title: str | None = None,
        visible_text: str | None = None,
    ) -> DetectionResult:
        # Match against URL, title, or reference
        combined_signal = f"{url} {target_reference} {page_title or ''} {visible_text or ''}"
        return self._determine_mock_outcome(combined_signal)

    def analyze_email(
        self,
        *,
        sender: str | None = None,
        subject: str | None = None,
        body_text: str | None = None,
        links: list[str] | None = None,
        primary_domain: str = "email-scan",
    ) -> DetectionResult:
        # Match against combined email content
        combined_signal = f"{sender or ''} {subject or ''} {body_text or ''} {' '.join(links or [])}"
        return self._determine_mock_outcome(combined_signal)
