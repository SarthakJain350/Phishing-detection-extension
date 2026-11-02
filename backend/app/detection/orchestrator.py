
"""Detection orchestration using deterministic heuristics and optional Gemini."""

from __future__ import annotations

import abc
from dataclasses import dataclass
import logging
import time

from backend.app.detection.heuristics import DeterministicHeuristicsEngine
from backend.app.providers.gemini import GeminiAdapter
from backend.app.schemas.scan import (
    EvidenceItem,
    ToolStatusDetail,
    ToolStatuses,
)

logger = logging.getLogger(__name__)


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
        raise NotImplementedError


class RealDetectionOrchestrator(BaseDetectionOrchestrator):
    """Combines deterministic evidence with optional Gemini analysis."""

    def __init__(
        self,
        heuristics: DeterministicHeuristicsEngine | None = None,
        gemini: GeminiAdapter | None = None,
        reputation: Any | None = None,
    ) -> None:
        self._heuristics = heuristics or DeterministicHeuristicsEngine()
        self._gemini = gemini or GeminiAdapter()
        self._reputation = reputation

    @staticmethod
    def _heuristic_score(evidence: list[EvidenceItem]) -> int | None:
        if not evidence:
            return None

        severity_scores = {"low": 25, "medium": 50, "high": 75}
        strongest = max(
            severity_scores.get(item.severity, 25) for item in evidence
        )
        additional_findings = min(max(len(evidence) - 1, 0) * 5, 20)
        return min(strongest + additional_findings, 95)

    @staticmethod
    def _classification_for_score(score: int, has_evidence: bool) -> str:
        if score >= 70:
            return "phishing"
        if score >= 40 or has_evidence:
            return "suspicious"
        return "likely_legitimate"

    def _combine(
        self,
        evidence: list[EvidenceItem],
        llm_result,
        llm_status: ToolStatusDetail,
        reputation_status: ToolStatusDetail | None = None,
    ) -> DetectionResult:
        if reputation_status is None:
            reputation_status = ToolStatusDetail(
                status="unavailable",
                reason_code="provider_not_integrated",
            )

        heuristic_score = self._heuristic_score(evidence)
        llm_score = llm_result.risk_score if llm_result is not None else None

        if heuristic_score is None and llm_score is None:
            unavail_reasons = [
                "No usable assessment was produced. This does not establish that the target is safe."
            ]
            if llm_status.status == "timeout":
                unavail_reasons.append(
                    "Content analysis timed out and could not be completed."
                )
            elif llm_status.status == "error":
                unavail_reasons.append(
                    "Content analysis encountered a service error and could not be completed."
                )
            elif llm_status.reason_code == "no_api_key":
                unavail_reasons.append(
                    "Content analysis is not configured."
                )

            if reputation_status.reason_code == "provider_not_integrated":
                unavail_reasons.append(
                    "Reputation checking is not integrated, so this assessment does not include a reputation lookup."
                )
            elif reputation_status.status == "timeout":
                unavail_reasons.append(
                    "Reputation lookup timed out and could not be completed."
                )
            elif reputation_status.status == "error":
                unavail_reasons.append(
                    "Reputation lookup encountered a service error and could not be completed."
                )

            return DetectionResult(
                classification=None,
                risk_score=None,
                reasons=unavail_reasons,
                evidence=evidence,
                tool_statuses=ToolStatuses(
                    heuristics=ToolStatusDetail(status="complete"),
                    reputation=reputation_status,
                    llm=llm_status,
                ),
                analysis_status="unavailable",
            )

        if heuristic_score is None:
            score = llm_score
        elif llm_score is None:
            score = heuristic_score
        else:
            # Retain the stronger signal rather than letting a low LLM score
            # erase deterministic evidence.
            score = max(heuristic_score, llm_score)

        assert score is not None
        classification = self._classification_for_score(
            score,
            has_evidence=bool(evidence),
        )

        reasons = [item.explanation for item in evidence if item.explanation]

        if llm_result is not None:
            reasons.extend(
                reason for reason in llm_result.reasons if reason not in reasons
            )

        if not reasons:
            reasons.append(
                "The available model assessment is advisory and does not guarantee safety."
            )

        # Distinguish LLM provider failure vs missing configuration
        if llm_result is None:
            if llm_status.status == "timeout":
                reasons.append(
                    "Content analysis timed out; this assessment uses deterministic heuristics only."
                )
            elif llm_status.status == "error":
                reasons.append(
                    "Content analysis encountered a service error; this assessment uses deterministic heuristics only."
                )
            elif llm_status.reason_code == "no_api_key":
                reasons.append(
                    "Gemini API key is not configured; this assessment uses deterministic heuristics only."
                )
            else:
                reasons.append(
                    "Gemini analysis was unavailable; this assessment uses deterministic heuristics only."
                )

        # Distinguish Reputation unintegrated vs runtime failure (timeout, network error, service error)
        if reputation_status.reason_code == "provider_not_integrated":
            reasons.append(
                "Reputation checking is not integrated, so this assessment does not include a reputation lookup."
            )
        elif reputation_status.status == "timeout":
            reasons.append(
                "Reputation lookup timed out and could not be completed."
            )
        elif reputation_status.status == "error":
            reasons.append(
                "Reputation lookup encountered a service error and could not be completed."
            )
        elif reputation_status.status == "unavailable":
            reasons.append(
                f"Reputation lookup was unavailable ({reputation_status.reason_code or 'service_unavailable'})."
            )

        all_complete = (
            reputation_status.status == "complete"
            and llm_status.status == "complete"
        )
        analysis_status = "complete" if all_complete else "partial"

        return DetectionResult(
            classification=classification,
            risk_score=max(0, min(100, score)),
            reasons=reasons,
            evidence=evidence,
            tool_statuses=ToolStatuses(
                heuristics=ToolStatusDetail(status="complete"),
                reputation=reputation_status,
                llm=llm_status,
            ),
            analysis_status=analysis_status,
        )

    def analyze_website(
        self,
        *,
        url: str,
        target_reference: str,
        page_title: str | None = None,
        visible_text: str | None = None,
    ) -> DetectionResult:
        started = time.monotonic()

        evidence = self._heuristics.analyze_website(
            url=url,
            target_reference=target_reference,
            page_title=page_title,
            visible_text=visible_text,
        )
        logger.debug("Heuristics evaluation completed in %.2fs", time.monotonic() - started)

        started = time.monotonic()
        llm_result, llm_status = self._gemini.analyze_target(
            target_type="website",
            url_or_domain=target_reference,
            title=page_title,
            text=visible_text,
        )
        logger.debug("Gemini analysis completed in %.2fs", time.monotonic() - started)

        reputation_status: ToolStatusDetail
        if self._reputation is not None:
            started = time.monotonic()
            try:
                _, reputation_status = self._reputation.check_reputation(
                    target_reference=target_reference,
                    url=url,
                )
            except Exception as exc:
                logger.warning("Reputation provider raised exception: %s", exc)
                reputation_status = ToolStatusDetail(
                    status="error",
                    reason_code="provider_exception",
                )
            logger.debug("Reputation lookup completed in %.2fs", time.monotonic() - started)
        else:
            reputation_status = ToolStatusDetail(
                status="unavailable",
                reason_code="provider_not_integrated",
            )

        started = time.monotonic()
        result = self._combine(
            evidence=evidence,
            llm_result=llm_result,
            llm_status=llm_status,
            reputation_status=reputation_status,
        )
        logger.debug("Evidence combination completed in %.2fs", time.monotonic() - started)

        return result

    def analyze_email(
        self,
        *,
        sender: str | None = None,
        subject: str | None = None,
        body_text: str | None = None,
        links: list[str] | None = None,
        primary_domain: str = "email-scan",
    ) -> DetectionResult:
        email_links = links or []
        evidence = self._heuristics.analyze_email(
            sender=sender,
            subject=subject,
            body_text=body_text,
            links=email_links,
        )

        # Send bounded message content and the existing primary reference.
        # Do not send full link URLs, which may contain private query tokens.
        llm_text = "\n".join(
            part
            for part in (
                f"Sender: {sender}" if sender else "",
                f"Links: {len(email_links)} extracted link(s)",
                body_text,
            )
            if part
        )[:3000]

        llm_result, llm_status = self._gemini.analyze_target(
            target_type="email",
            url_or_domain=primary_domain,
            title=subject,
            text=llm_text or None,
        )

        reputation_status: ToolStatusDetail
        if self._reputation is not None:
            try:
                _, reputation_status = self._reputation.check_reputation(
                    target_reference=primary_domain,
                    url=primary_domain,
                )
            except Exception as exc:
                logger.warning("Reputation provider raised exception: %s", exc)
                reputation_status = ToolStatusDetail(
                    status="error",
                    reason_code="provider_exception",
                )
        else:
            reputation_status = ToolStatusDetail(
                status="unavailable",
                reason_code="provider_not_integrated",
            )

        return self._combine(
            evidence=evidence,
            llm_result=llm_result,
            llm_status=llm_status,
            reputation_status=reputation_status,
        )


class MockDetectionOrchestrator(BaseDetectionOrchestrator):
    """Deterministic fixture orchestrator for tests only."""

    def _result(self, signal_text: str) -> DetectionResult:
        lowered = signal_text.lower()

        if "unavailable" in lowered:
            return DetectionResult(
                classification=None,
                risk_score=None,
                reasons=["Fixture: analysis unavailable."],
                evidence=[],
                tool_statuses=ToolStatuses(
                    heuristics=ToolStatusDetail(
                        status="unavailable", reason_code="service_down"
                    ),
                    reputation=ToolStatusDetail(
                        status="unavailable", reason_code="provider_timeout"
                    ),
                    llm=ToolStatusDetail(
                        status="unavailable", reason_code="quota_exceeded"
                    ),
                ),
                analysis_status="unavailable",
            )

        if "phish" in lowered or "danger" in lowered:
            classification, score = "phishing", 88
        elif "suspicious" in lowered:
            classification, score = "suspicious", 55
        else:
            classification, score = "likely_legitimate", 12

        return DetectionResult(
            classification=classification,
            risk_score=score,
            reasons=["Fixture result; not a real security assessment."],
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
        return self._result(
            f"{url} {target_reference} {page_title or ''} {visible_text or ''}"
        )

    def analyze_email(
        self,
        *,
        sender: str | None = None,
        subject: str | None = None,
        body_text: str | None = None,
        links: list[str] | None = None,
        primary_domain: str = "email-scan",
    ) -> DetectionResult:
        return self._result(
            f"{sender or ''} {subject or ''} {body_text or ''} {' '.join(links or [])}"
        )
