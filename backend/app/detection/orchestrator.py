
"""Detection orchestration using deterministic heuristics and optional Gemini."""

from __future__ import annotations

import abc
from dataclasses import dataclass
import logging
import time
from typing import TYPE_CHECKING, Any

from backend.app.detection.heuristics import DeterministicHeuristicsEngine
from backend.app.providers.gemini import GeminiAdapter
from backend.app.schemas.scan import (
    EvidenceItem,
    ToolStatusDetail,
    ToolStatuses,
)

if TYPE_CHECKING:
    from backend.app.providers.safe_browsing import SafeBrowsingAdapter

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
    opt_in_gemini: bool = True,
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
        opt_in_gemini: bool = False,
    ) -> DetectionResult:
        raise NotImplementedError


class RealDetectionOrchestrator(BaseDetectionOrchestrator):
    """Combines deterministic evidence with optional Gemini analysis."""

    def __init__(
        self,
        heuristics: DeterministicHeuristicsEngine | None = None,
        gemini: GeminiAdapter | None = None,
        reputation: SafeBrowsingAdapter | Any | None = None,
    ) -> None:
        self._heuristics = heuristics or DeterministicHeuristicsEngine()
        self._gemini = gemini or GeminiAdapter()
        self._reputation = reputation

    @staticmethod
    def _heuristic_score(evidence: list[EvidenceItem]) -> int | None:
        if not evidence:
            return None

        severity_scores = {"low": 25, "medium": 50, "high": 75}

        # Deduplicate risk scoring by heuristic rule code (item.type) within a scan.
        # Repeated instances of the same heuristic rule code must not independently
        # inflate the risk score.
        rule_scores: dict[str, int] = {}
        for item in evidence:
            score = severity_scores.get(item.severity, 25)
            rule_type = item.type
            if rule_type not in rule_scores or score > rule_scores[rule_type]:
                rule_scores[rule_type] = score

        strongest = max(rule_scores.values())
        # Independent heuristic categories beyond the first contribute 5 points each, capped at 20.
        additional_categories = max(len(rule_scores) - 1, 0)
        additional_findings = min(additional_categories * 5, 20)
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
        reputation_evidence: list[EvidenceItem] | None = None,
        target_type: str = "website",
        heuristics_status: ToolStatusDetail | None = None,
    ) -> DetectionResult:
        if heuristics_status is None:
            heuristics_status = ToolStatusDetail(status="complete")
        if reputation_status is None:
            reputation_status = ToolStatusDetail(
                status="unavailable",
                reason_code="provider_not_integrated",
            )

        # ---------------------------------------------------------------------------
        # Scoring rule: merge reputation evidence with heuristic evidence.
        #
        # Aggregation design:
        #   - Reputation evidence (source="reputation") is appended to heuristic
        #     evidence ONLY when the provider completed successfully and returned
        #     findings. The combined list is scored by _heuristic_score() as a unit.
        #   - A single "high" severity reputation hit adds 75 base points.
        #     Combined with the additional_findings bonus this can reach up to 80,
        #     sufficient to cross the phishing threshold (>= 70).
        #   - Provider failure / timeout / unavailable -> empty list -> no score
        #     impact. A failed lookup is NEVER treated as clean evidence.
        #   - Double-counting is avoided: reputation items carry source="reputation"
        #     (distinct from source="heuristics"), and both sets are merged before
        #     a single call to _heuristic_score(). The LLM score is combined via
        #     max() and cannot lower a score already raised by reputation.
        #   - The final score is clamped to 0-100 before returning.
        # ---------------------------------------------------------------------------
        rep_items = (
            [item for item in reputation_evidence if isinstance(item, EvidenceItem)]
            if isinstance(reputation_evidence, list)
            else []
        )
        all_evidence: list[EvidenceItem] = list(evidence) + rep_items

        heuristic_score = self._heuristic_score(all_evidence)
        llm_score = llm_result.risk_score if llm_result is not None else None

        if heuristic_score is None and llm_score is None:
            # 1. Distinguish execution failures:
            # - Heuristics raised an internal exception or did not complete.
            # - Gemini or Reputation suffered a runtime timeout or error.
            heuristics_failed = heuristics_status.status != "complete"
            llm_runtime_failed = llm_status.status in ("timeout", "error")
            reputation_runtime_failed = reputation_status.status in ("timeout", "error")

            is_runtime_failure = (
                heuristics_failed
                or llm_runtime_failed
                or reputation_runtime_failed
            )

            # 2. When heuristics ran to completion and found zero suspicious indicators,
            # and external providers were intentionally skipped (e.g. Gemini opt-in disabled
            # for email) or not integrated (email reputation), produce an inconclusive
            # partial analysis rather than treating it as an unavailable operational error.
            is_intentional_skip = (
                target_type == "email"
                or llm_status.reason_code == "opt_in_required"
            )

            if not is_runtime_failure and is_intentional_skip:
                partial_reasons = [
                    "Deterministic heuristics completed without finding suspicious indicators."
                ]
                if llm_status.reason_code == "opt_in_required":
                    partial_reasons.append(
                        "External AI content analysis is disabled (opt-in required)."
                    )
                elif llm_status.reason_code == "no_api_key":
                    partial_reasons.append(
                        "Content analysis is not configured."
                    )

                if reputation_status.reason_code == "provider_not_integrated":
                    partial_reasons.append(
                        "Reputation checking is not integrated, so this assessment does not include a reputation lookup."
                    )
                elif reputation_status.status == "unavailable":
                    partial_reasons.append(
                        f"Reputation lookup was unavailable ({reputation_status.reason_code or 'service_unavailable'})."
                    )

                partial_reasons.append(
                    "This assessment is inconclusive and does not establish that the target is safe."
                )

                return DetectionResult(
                    classification=None,
                    risk_score=None,
                    reasons=partial_reasons,
                    evidence=all_evidence,
                    tool_statuses=ToolStatuses(
                        heuristics=heuristics_status,
                        reputation=reputation_status,
                        llm=llm_status,
                    ),
                    analysis_status="partial",
                )

            # Otherwise (actual heuristic failure, LLM timeout/error, or unavailable website analysis):
            unavail_reasons = [
                "No usable assessment was produced. This does not establish that the target is safe."
            ]
            if heuristics_status.status == "error":
                unavail_reasons.append(
                    "Deterministic heuristics encountered an internal error and could not be completed."
                )
            elif heuristics_status.status != "complete":
                unavail_reasons.append(
                    "Deterministic heuristics could not be completed."
                )

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
            elif llm_status.reason_code == "opt_in_required":
                unavail_reasons.append(
                    "External AI content analysis is disabled (opt-in required)."
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
                evidence=all_evidence,
                tool_statuses=ToolStatuses(
                    heuristics=heuristics_status,
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
            has_evidence=bool(all_evidence),
        )

        reasons = list(dict.fromkeys(item.explanation for item in all_evidence if item.explanation))

        if llm_result is not None:
            if target_type == "email":
                # Privacy guardrail for email scans:
                # Map recognized model outcome to predefined sanitized advisory summaries.
                # Never append arbitrary or raw LLM-generated reason strings to persisted reasons.
                sanitized_email_reasons = []
                if llm_result.classification == "phishing":
                    sanitized_email_reasons.append(
                        "AI content analysis detected patterns strongly associated with deceptive phishing communication."
                    )
                elif llm_result.classification == "suspicious":
                    sanitized_email_reasons.append(
                        "AI content analysis noted unusual communication characteristics requiring caution."
                    )
                elif llm_result.classification == "likely_legitimate":
                    sanitized_email_reasons.append(
                        "AI content analysis did not detect strong social-engineering indicators."
                    )
                for sr in sanitized_email_reasons:
                    if sr not in reasons:
                        reasons.append(sr)
            else:
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
            evidence=all_evidence,
            tool_statuses=ToolStatuses(
                heuristics=heuristics_status,
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
    opt_in_gemini: bool = True,
    ) -> DetectionResult:
        started = time.monotonic()

        try:
            evidence = self._heuristics.analyze_website(
                url=url,
                target_reference=target_reference,
                page_title=page_title,
                visible_text=visible_text,
            )
            heuristics_status = ToolStatusDetail(status="complete")
        except Exception as exc:
            logger.exception("Heuristics evaluation failed for website scan: %s", exc)
            evidence = []
            heuristics_status = ToolStatusDetail(
                status="error",
                reason_code="heuristics_exception",
            )
        logger.debug("Heuristics evaluation completed in %.2fs", time.monotonic() - started)

        if opt_in_gemini:
            started = time.monotonic()
            llm_result, llm_status = self._gemini.analyze_target(
                target_type="website",
                url_or_domain=target_reference,
                title=page_title,
                text=visible_text,
            )
            logger.debug("Gemini analysis completed in %.2fs", time.monotonic() - started)
        else:
            llm_result = None
            llm_status = ToolStatusDetail(
                status="unavailable",
                reason_code="opt_in_required",
            )

        reputation_status: ToolStatusDetail
        reputation_evidence: list[EvidenceItem] = []
        if self._reputation is not None:
            started = time.monotonic()
            try:
                rep_result, reputation_status = self._reputation.check_reputation(
                    target_reference=target_reference,
                    url=url,
                )
                reputation_evidence = (
                    rep_result if isinstance(rep_result, list) else []
                )
            except Exception as exc:
                logger.warning("Reputation provider raised exception: %s", type(exc).__name__)
                reputation_evidence = []
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
            reputation_evidence=reputation_evidence,
            target_type="website",
            heuristics_status=heuristics_status,
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
        opt_in_gemini: bool = False,
    ) -> DetectionResult:
        email_links = links or []
        try:
            evidence = self._heuristics.analyze_email(
                sender=sender,
                subject=subject,
                body_text=body_text,
                links=email_links,
            )
            heuristics_status = ToolStatusDetail(status="complete")
        except Exception as exc:
            logger.exception("Heuristics evaluation failed for email scan: %s", exc)
            evidence = []
            heuristics_status = ToolStatusDetail(
                status="error",
                reason_code="heuristics_exception",
            )

        if opt_in_gemini:
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
        else:
            llm_result = None
            llm_status = ToolStatusDetail(
                status="unavailable",
                reason_code="opt_in_required",
            )

        # Phase 1: Email reputation integration is strictly out of scope.
        # Email scans must not invoke the website reputation adapter.
        reputation_status = ToolStatusDetail(
            status="unavailable",
            reason_code="provider_not_integrated",
        )

        return self._combine(
            evidence=evidence,
            llm_result=llm_result,
            llm_status=llm_status,
            reputation_status=reputation_status,
            target_type="email",
            heuristics_status=heuristics_status,
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
        opt_in_gemini: bool = False,
    ) -> DetectionResult:
        return self._result(
            f"{sender or ''} {subject or ''} {body_text or ''} {' '.join(links or [])}"
        )
