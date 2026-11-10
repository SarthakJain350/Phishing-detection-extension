"""Integration tests for FastAPI API v1 endpoints and request validation."""

from __future__ import annotations

import uuid
import pytest
from sqlalchemy import text
from sqlalchemy.orm import Session

from backend.app.db.models import ScanRecord
from backend.app.db.session import get_db
from backend.app.main import app


class TestHealthEndpoints:
    """Verify liveness and readiness probes."""

    def test_health_liveness(self, client):
        response = client.get("/api/v1/health")
        assert response.status_code == 200
        assert response.json() == {"status": "ok"}

    def test_health_readiness_connected(self, client):
        response = client.get("/api/v1/health/ready")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ready"
        assert data["database"] == "connected"

    def test_health_readiness_database_failure(self, client):
        """Verify that when database is unavailable, readiness returns 503 structured error."""
        class FailingSession:
            def execute(self, *args, **kwargs):
                raise RuntimeError("Database connection timed out.")

        def broken_get_db():
            yield FailingSession()

        app.dependency_overrides[get_db] = broken_get_db
        try:
            response = client.get("/api/v1/health/ready")
            assert response.status_code == 503
            data = response.json()
            assert data["error"]["code"] == "SERVICE_UNAVAILABLE"
            assert "Database readiness check failed" in data["error"]["message"]
        finally:
            app.dependency_overrides.clear()



class TestWebsiteScanDeterministicOutcomes:
    """Verify all 4 deterministic mock outcomes and full response contract compliance."""

def test_phishing_outcome(client, sqlite_session):
    payload = {
        "url": "https://paypal-security-check.phish-alert.com/login",
        "page_title": "Sign In",
        "source": "manual_website",
    }
    response = client.post("/api/v1/scans/website", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["classification"] == "phishing"
    assert data["risk_score"] >= 70
    assert data["analysis_status"] == "partial"
    assert data["target_type"] == "website"
    assert len(data["reasons"]) >= 1
    assert any(
        item["type"] == "misleading_subdomain"
        and item["severity"] == "high"
        for item in data["evidence"]
    )
    assert data["tool_statuses"]["heuristics"]["status"] == "complete"
    assert data["tool_statuses"]["reputation"]["status"] == "unavailable"
    assert data["tool_statuses"]["llm"]["status"] == "unavailable"

    scan_id = uuid.UUID(data["scan_id"])
    record = sqlite_session.query(ScanRecord).filter_by(id=scan_id).first()
    assert record is not None
    assert record.classification == "phishing"
    assert record.risk_score == data["risk_score"]
    assert record.analysis_status == "partial"


def test_suspicious_outcome(client):
    payload = {
        "url": "https://suspicious-billing-portal.net/invoice",
        "source": "manual_website",
    }
    response = client.post("/api/v1/scans/website", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["classification"] is None
    assert data["risk_score"] is None
    assert data["analysis_status"] == "unavailable"
    assert data["tool_statuses"]["heuristics"]["status"] == "complete"
    assert data["tool_statuses"]["reputation"]["status"] == "unavailable"
    assert data["tool_statuses"]["llm"]["status"] == "unavailable"


def test_unavailable_outcome_nullable_contract(client, sqlite_session):
    """Verify unavailable analysis returns NULL classification and risk score."""
    payload = {
        "url": "https://unavailable-upstream-service.org/check",
        "source": "manual_website",
    }
    response = client.post("/api/v1/scans/website", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["analysis_status"] == "unavailable"
    assert data["classification"] is None
    assert data["risk_score"] is None
    assert data["tool_statuses"]["llm"]["status"] == "unavailable"

    scan_id = uuid.UUID(data["scan_id"])
    record = sqlite_session.query(ScanRecord).filter_by(id=scan_id).first()
    assert record is not None
    assert record.classification is None
    assert record.risk_score is None
    assert record.analysis_status == "unavailable"


def test_likely_legitimate_outcome(client):
    payload = {
        "url": "https://en.wikipedia.org/wiki/Computer_security",
        "page_title": "Wikipedia",
        "source": "auto_website",
    }
    response = client.post("/api/v1/scans/website", json=payload)
    assert response.status_code == 200
    data = response.json()

    assert data["classification"] is None
    assert data["risk_score"] is None
    assert data["analysis_status"] == "unavailable"
    assert data["tool_statuses"]["heuristics"]["status"] == "complete"
    assert data["tool_statuses"]["reputation"]["status"] == "unavailable"
    assert data["tool_statuses"]["llm"]["status"] == "unavailable"


class TestWebsiteRequestValidation:
    """Verify strict request validation returning standardized HTTP 400 errors."""

    def test_empty_url_returns_400(self, client):
        response = client.post("/api/v1/scans/website", json={"url": ""})
        assert response.status_code == 400
        data = response.json()
        assert data["error"]["code"] == "VALIDATION_ERROR"
        assert "url" in data["error"]["message"].lower()

    def test_invalid_scheme_returns_400(self, client):
        invalid_schemes = [
            "ftp://files.example.com",
            "javascript:alert(1)",
            "data:text/html,test",
            "file:///etc/passwd",
        ]
        for url in invalid_schemes:
            response = client.post("/api/v1/scans/website", json={"url": url})
            assert response.status_code == 400
            data = response.json()
            assert data["error"]["code"] == "VALIDATION_ERROR"
            assert "scheme" in data["error"]["message"].lower()

    def test_oversize_url_returns_400(self, client):
        long_url = "https://example.com/" + "a" * 2050
        response = client.post("/api/v1/scans/website", json={"url": long_url})
        assert response.status_code == 400
        data = response.json()
        assert data["error"]["code"] == "VALIDATION_ERROR"
    def test_oversize_title_and_text_returns_400(self, client):
        # Oversize page_title > 256
        res_title = client.post(
            "/api/v1/scans/website",
            json={"url": "https://example.com", "page_title": "T" * 300},
        )
        assert res_title.status_code == 400
        assert res_title.json()["error"]["code"] == "VALIDATION_ERROR"

        # Oversize visible_text > 2000
        res_text = client.post(
            "/api/v1/scans/website",
            json={"url": "https://example.com", "visible_text": "B" * 2500},
        )
        assert res_text.status_code == 400
        assert res_text.json()["error"]["code"] == "VALIDATION_ERROR"

    def test_invalid_source_returns_400(self, client):
        response = client.post(
            "/api/v1/scans/website",
            json={"url": "https://example.com", "source": "unsupported_source"},
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"


class TestEmailScanValidationAndPersistence:
    """Verify email indicators scan endpoint."""

    def test_valid_email_scan(self, client, sqlite_session):
        payload = {
            "sender": "security-alert@paypal-update.com",
            "subject": "Urgent: Review your account",
            "body_text": "Please confirm your password immediately.",
            "links": ["https://paypal-update.com/login?token=abc"],
            "source": "gmail",
        }
        response = client.post("/api/v1/scans/email", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["target_type"] == "email"
        assert data["target_reference"] == "paypal-update.com"
        assert data["source"] == "gmail"

        # Verify DB record
        scan_id = uuid.UUID(data["scan_id"])
        record = sqlite_session.query(ScanRecord).filter_by(id=scan_id).first()
        assert record is not None
        assert record.target_reference == "paypal-update.com"
        assert record.target_type == "email"

    def test_oversize_links_count_returns_400(self, client):
        links = [f"https://link-{i}.com" for i in range(12)]  # Capped at 10
        response = client.post(
            "/api/v1/scans/email",
            json={"subject": "Test", "links": links},
        )
        assert response.status_code == 400
        assert response.json()["error"]["code"] == "VALIDATION_ERROR"

    def test_email_scan_gemini_opt_in_default_false(self, client):
        """Verify that Gemini LLM analysis is skipped by default for email scans."""
        payload = {
            "sender": "alerts@example.com",
            "subject": "Routine Notice",
            "body_text": "Nothing suspicious here.",
            "source": "gmail",
        }
        response = client.post("/api/v1/scans/email", json=payload)
        assert response.status_code == 200
        data = response.json()
        assert data["tool_statuses"]["llm"]["status"] == "unavailable"
        assert data["tool_statuses"]["llm"]["reason_code"] == "opt_in_required"


class TestScanHistoryAndPagination:
    """Verify listing recent scans with pagination and ordering."""

    def test_list_scans_pagination(self, client):
        # Insert 5 test scans
        for i in range(5):
            client.post("/api/v1/scans/website", json={"url": f"https://site-{i}.org"})

        # Query first page limit=2
        res_page1 = client.get("/api/v1/scans?limit=2&offset=0")
        assert res_page1.status_code == 200
        data_p1 = res_page1.json()
        assert data_p1["limit"] == 2
        assert data_p1["offset"] == 0
        assert len(data_p1["items"]) == 2
        assert data_p1["total"] >= 5

        # Query second page offset=2
        res_page2 = client.get("/api/v1/scans?limit=2&offset=2")
        assert res_page2.status_code == 200
        data_p2 = res_page2.json()
        assert len(data_p2["items"]) == 2
        assert data_p2["items"][0]["scan_id"] != data_p1["items"][0]["scan_id"]

    def test_pagination_bounds_validation(self, client):
        # limit=0 -> 400
        assert client.get("/api/v1/scans?limit=0").status_code == 400
        # limit=150 (> 100) -> 400
        assert client.get("/api/v1/scans?limit=150").status_code == 400
        # offset=-1 -> 400
        assert client.get("/api/v1/scans?offset=-1").status_code == 400

    
    def test_clear_scan_history(self, client):
        # Create test scans
        for i in range(3):
            response = client.post(
                "/api/v1/scans/website",
                json={"url": f"https://clear-test-{i}.com"},
            )
            assert response.status_code == 200

        # Clear all scan history
        delete_response = client.delete("/api/v1/scans")
        assert delete_response.status_code == 200

        data = delete_response.json()
        assert data["message"] == "Scan history cleared successfully."
        assert data["deleted_count"] == 3
        history_response = client.get("/api/v1/scans")
        assert history_response.status_code == 200
        assert history_response.json()["total"] == 0
        # Verify history is empty
        history_response = client.get("/api/v1/scans")
        assert history_response.status_code == 200
        assert history_response.json()["total"] == 0
        assert history_response.json()["items"] == []

    def test_clear_empty_scan_history(self, client):
        response = client.delete("/api/v1/scans")

        assert response.status_code == 200
        assert response.json()["deleted_count"] == 0

class TestSingleScanLookup:
    """Verify retrieval of single scan by UUID."""

    def test_get_existing_scan(self, client):
        create_res = client.post("/api/v1/scans/website", json={"url": "https://lookup-test.com"})
        scan_id = create_res.json()["scan_id"]

        get_res = client.get(f"/api/v1/scans/{scan_id}")
        assert get_res.status_code == 200
        assert get_res.json()["scan_id"] == scan_id
        assert get_res.json()["target_reference"] == "lookup-test.com"

    def test_get_nonexistent_scan_returns_404(self, client):
        missing_uuid = str(uuid.uuid4())
        response = client.get(f"/api/v1/scans/{missing_uuid}")
        assert response.status_code == 404
        data = response.json()
        assert data["error"]["code"] == "NOT_FOUND"

    def test_get_malformed_uuid_returns_400(self, client):
        response = client.get("/api/v1/scans/not-a-valid-uuid")
        assert response.status_code == 400
        data = response.json()
        assert data["error"]["code"] == "VALIDATION_ERROR"


class TestPrivacyAndSecurityEnforcement:
    """Verify that full URLs, query strings, and page/email bodies are NEVER persisted."""

    def test_privacy_boundary_no_full_urls_in_database(self, client, sqlite_session):
        sensitive_token = "SESSION_TOKEN_SECRET_987654321"
        sensitive_page_text = "CONFIDENTIAL_PASSWORD_RESET_BODY"

        payload = {
            "url": f"https://bank.example.com/login?token={sensitive_token}&user=alice",
            "page_title": "Sign In Portal",
            "visible_text": sensitive_page_text,
            "source": "manual_website",
        }
        response = client.post("/api/v1/scans/website", json=payload)
        assert response.status_code == 200
        scan_id = uuid.UUID(response.json()["scan_id"])

        # Fetch raw database row
        row = sqlite_session.query(ScanRecord).filter_by(id=scan_id).first()
        assert row is not None

        # Verify target_reference has only hostname
        assert row.target_reference == "bank.example.com"

        # Check raw text representations of all row attributes
        row_str = f"{row.target_reference} {row.evidence} {row.tool_statuses} {row.classification} {row.source}"
        assert sensitive_token not in row_str
        assert sensitive_page_text not in row_str
        assert "login" not in row.target_reference
        assert "token=" not in row_str

    def test_cors_headers_strict(self, client):
        """Verify CORS allows configured origins and does NOT permit wildcard *."""
        # Configured origin: http://localhost:3000
        response = client.options(
            "/api/v1/health",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert response.headers.get("access-control-allow-origin") == "http://localhost:3000"

        # Unconfigured origin: should NOT return wildcard '*'
        untrusted_response = client.options(
            "/api/v1/health",
            headers={
                "Origin": "http://evil-attacker-site.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert untrusted_response.headers.get("access-control-allow-origin") != "*"

    def test_unhandled_server_error_returns_safe_500(self):
        """Verify unexpected exceptions return safe 500 without leaking stack traces or internal secrets."""
        from starlette.testclient import TestClient
        from backend.app.api.v1.scans import get_orchestrator

        safe_client = TestClient(app, raise_server_exceptions=False)

        def broken_orchestrator():
            raise RuntimeError("TOP_SECRET_INTERNAL_DATABASE_CREDENTIAL")

        app.dependency_overrides[get_orchestrator] = broken_orchestrator
        try:
            response = safe_client.post(
                "/api/v1/scans/website",
                json={"url": "https://example.com", "source": "manual_website"},
            )
            assert response.status_code == 500
            data = response.json()
            assert data["error"]["code"] == "INTERNAL_SERVER_ERROR"
            assert data["error"]["message"] == "An unexpected server error occurred."
            # Crucial: verify internal exception message and traceback are not leaked
            assert "TOP_SECRET_INTERNAL_DATABASE_CREDENTIAL" not in response.text
            assert "Traceback" not in response.text
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)


class TestSafeBrowsingAndScoringBehavior:
    """Verify behavior on documented Safe Browsing test cases, scoring combination, and missing checks."""

    SAFE_BROWSING_SOCIAL_ENGINEERING_URL = (
        "http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/SOCIAL_ENGINEERING/URL/"
    )

    def test_safebrowsing_test_url_under_current_signals_returns_partial_status(self, client):
        """Under current signals (heuristics + LLM with low score, reputation unintegrated):
        The test URL has no deceptive brand keywords or structural URL anomalies in its hostname.
        Heuristics return 0 evidence without falsely labeling all appspot.com domains as phishing.
        Because reputation is unintegrated, analysis_status MUST be 'partial' with explicit disclaimer.
        """
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.providers.gemini import GeminiAnalysisResult
        from backend.app.schemas.scan import ToolStatusDetail

        class CleanGemini:
            def analyze_target(self, **kwargs):
                return (
                    GeminiAnalysisResult(
                        classification="likely_legitimate",
                        risk_score=10,
                        reasons=["No obvious phishing indicators identified in target hostname."],
                        confidence_label="medium",
                    ),
                    ToolStatusDetail(status="complete"),
                )

        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(gemini=CleanGemini())
        try:
            response = client.post(
                "/api/v1/scans/website",
                json={
                    "url": self.SAFE_BROWSING_SOCIAL_ENGINEERING_URL,
                    "source": "manual_website",
                },
            )
            assert response.status_code == 200
            data = response.json()

            # Target reference is correctly normalized to hostname only
            assert data["target_reference"] == "testsafebrowsing.appspot.com"

            # Offline heuristics produce no false positive evidence on appspot.com
            assert data["evidence"] == []
            assert data["tool_statuses"]["heuristics"]["status"] == "complete"

            # Crucial: Reputation check was NOT run and is explicitly marked unavailable
            assert data["tool_statuses"]["reputation"]["status"] == "unavailable"
            assert data["tool_statuses"]["reputation"]["reason_code"] == "provider_not_integrated"

            # LLM completed
            assert data["tool_statuses"]["llm"]["status"] == "complete"

            # Status is partial because reputation is not integrated
            assert data["analysis_status"] == "partial"
            assert data["risk_score"] == 10
            assert data["classification"] == "likely_legitimate"

            # Explanatory reason informs user that reputation was not checked
            assert any("Reputation checking is not integrated" in r for r in data["reasons"])
            assert any("No obvious phishing indicators" in r for r in data["reasons"])
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)

    def test_safebrowsing_test_url_when_provider_detects_threat_promotes_to_phishing(self, client):
        """When an external detection provider flags the Safe Browsing test URL as social engineering,
        the orchestrator must combine the score and promote the verdict to 'phishing'.
        """
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.providers.gemini import GeminiAnalysisResult
        from backend.app.schemas.scan import ToolStatusDetail

        class ThreatDetectingGemini:
            def analyze_target(self, **kwargs):
                return (
                    GeminiAnalysisResult(
                        classification="phishing",
                        risk_score=85,
                        reasons=["Recognized social-engineering threat pattern."],
                        confidence_label="high",
                    ),
                    ToolStatusDetail(status="complete"),
                )

        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            gemini=ThreatDetectingGemini()
        )
        try:
            response = client.post(
                "/api/v1/scans/website",
                json={
                    "url": self.SAFE_BROWSING_SOCIAL_ENGINEERING_URL,
                    "source": "manual_website",
                },
            )
            assert response.status_code == 200
            data = response.json()

            assert data["classification"] == "phishing"
            assert data["risk_score"] == 85
            assert data["analysis_status"] == "partial"  # still partial because reputation tool is not integrated
            assert any("social-engineering" in r.lower() for r in data["reasons"])
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)

    def test_legitimate_appspot_and_standard_sites_produce_zero_false_heuristics(self):
        """Verify heuristics do not falsely flag appspot.com or Wikipedia domains."""
        from backend.app.detection.heuristics import DeterministicHeuristicsEngine

        engine = DeterministicHeuristicsEngine()

        for url, ref in [
            ("http://testsafebrowsing.appspot.com/apiv4/ANY_PLATFORM/SOCIAL_ENGINEERING/URL/", "testsafebrowsing.appspot.com"),
            ("https://my-legit-project.appspot.com/dashboard", "my-legit-project.appspot.com"),
            ("https://en.wikipedia.org/wiki/Computer_security", "en.wikipedia.org"),
            ("https://docs.python.org/3/library/index.html", "docs.python.org"),
        ]:
            evidence = engine.analyze_website(url=url, target_reference=ref)
            assert len(evidence) == 0, f"Unexpected false positive evidence on {url}: {evidence}"

    def test_heuristic_strong_evidence_cannot_be_erased_by_low_llm_score(self):
        """When heuristics find strong phishing evidence (score >= 70), a low LLM score
        (e.g. 10) must not erase the heuristic finding. The stronger signal must prevail.
        """
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.providers.gemini import GeminiAnalysisResult
        from backend.app.schemas.scan import EvidenceItem, ToolStatusDetail

        orch = RealDetectionOrchestrator()
        evidence = [
            EvidenceItem(
                type="misleading_subdomain",
                source="heuristics",
                severity="high",
                explanation="Subdomain impersonates PayPal on an unrelated domain.",
            )
        ]
        low_llm = GeminiAnalysisResult(
            classification="likely_legitimate",
            risk_score=10,
            reasons=["Model saw no problem."],
            confidence_label="low",
        )
        result = orch._combine(evidence, low_llm, ToolStatusDetail(status="complete"))

        # Heuristic score for high severity is 75; max(75, 10) = 75
        assert result.risk_score == 75
        assert result.classification == "phishing"
        assert result.analysis_status == "partial"
        assert any("PayPal" in r for r in result.reasons)

    def test_any_evidence_prevents_likely_legitimate_verdict(self):
        """Even with a low risk score, the presence of any heuristic evidence must
        prevent a 'likely_legitimate' verdict, escalating to at least 'suspicious'.
        """
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.providers.gemini import GeminiAnalysisResult
        from backend.app.schemas.scan import EvidenceItem, ToolStatusDetail

        orch = RealDetectionOrchestrator()
        evidence = [
            EvidenceItem(
                type="excessive_hyphens",
                source="heuristics",
                severity="low",
                explanation="Hostname contains multiple hyphens.",
            )
        ]
        low_llm = GeminiAnalysisResult(
            classification="likely_legitimate",
            risk_score=15,
            reasons=["Model saw no major threat."],
            confidence_label="low",
        )
        result = orch._combine(evidence, low_llm, ToolStatusDetail(status="complete"))

        # Having evidence prevents 'likely_legitimate'
        assert result.classification == "suspicious"
        assert result.risk_score >= 25
        assert result.analysis_status == "partial"

    def test_provider_runtime_failure_reputation_timeout_distinguished(self):
        """Verify reputation lookup timeout is distinguished from provider_not_integrated."""
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.providers.gemini import GeminiAnalysisResult
        from backend.app.schemas.scan import ToolStatusDetail

        class TimingOutReputation:
            def check_reputation(self, **kwargs):
                return None, ToolStatusDetail(status="timeout", reason_code="request_timeout")

        class CleanGemini:
            def analyze_target(self, **kwargs):
                return (
                    GeminiAnalysisResult(
                        classification="likely_legitimate",
                        risk_score=10,
                        reasons=["Clean target metadata."],
                        confidence_label="low",
                    ),
                    ToolStatusDetail(status="complete"),
                )

        orch = RealDetectionOrchestrator(
            gemini=CleanGemini(),
            reputation=TimingOutReputation(),
        )
        result = orch.analyze_website(
            url="https://example.com/login",
            target_reference="example.com",
        )

        assert result.analysis_status == "partial"
        assert result.tool_statuses.reputation.status == "timeout"
        assert result.tool_statuses.reputation.reason_code == "request_timeout"
        # Reason must explicitly describe the timeout, NOT 'provider_not_integrated'
        assert any("Reputation lookup timed out" in r for r in result.reasons)
        assert not any("provider_not_integrated" in r for r in result.reasons)

    def test_provider_runtime_failure_reputation_error_distinguished(self):
        """Verify reputation lookup error is distinguished from provider_not_integrated."""
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.providers.gemini import GeminiAnalysisResult
        from backend.app.schemas.scan import ToolStatusDetail

        class FailingReputation:
            def check_reputation(self, **kwargs):
                return None, ToolStatusDetail(status="error", reason_code="upstream_503")

        class CleanGemini:
            def analyze_target(self, **kwargs):
                return (
                    GeminiAnalysisResult(
                        classification="likely_legitimate",
                        risk_score=10,
                        reasons=["Clean target metadata."],
                        confidence_label="low",
                    ),
                    ToolStatusDetail(status="complete"),
                )

        orch = RealDetectionOrchestrator(
            gemini=CleanGemini(),
            reputation=FailingReputation(),
        )
        result = orch.analyze_website(
            url="https://example.com/login",
            target_reference="example.com",
        )

        assert result.analysis_status == "partial"
        assert result.tool_statuses.reputation.status == "error"
        assert any("Reputation lookup encountered a service error" in r for r in result.reasons)

    def test_provider_runtime_failure_llm_timeout_distinguished(self):
        """Verify LLM timeout generates specific failure reason instead of generic unavailable."""
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import ToolStatusDetail

        class TimingOutGemini:
            def analyze_target(self, **kwargs):
                return None, ToolStatusDetail(status="timeout", reason_code="request_timeout")

        orch = RealDetectionOrchestrator(gemini=TimingOutGemini())
        result = orch.analyze_website(
            url="https://example.com/login",
            target_reference="example.com",
        )

        assert result.analysis_status == "unavailable"
        assert result.tool_statuses.llm.status == "timeout"
        assert any("Content analysis timed out" in r for r in result.reasons)

    def test_all_providers_complete_produces_complete_status(self):
        """When heuristics, LLM, and reputation all complete, status must be 'complete'."""
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.providers.gemini import GeminiAnalysisResult
        from backend.app.schemas.scan import ToolStatusDetail

        class CompleteReputation:
            def check_reputation(self, **kwargs):
                return [], ToolStatusDetail(status="complete")

        class CompleteGemini:
            def analyze_target(self, **kwargs):
                return (
                    GeminiAnalysisResult(
                        classification="likely_legitimate",
                        risk_score=10,
                        reasons=["Clean target metadata."],
                        confidence_label="high",
                    ),
                    ToolStatusDetail(status="complete"),
                )

        orch = RealDetectionOrchestrator(
            gemini=CompleteGemini(),
            reputation=CompleteReputation(),
        )
        result = orch.analyze_website(
            url="https://example.com/login",
            target_reference="example.com",
        )

        assert result.analysis_status == "complete"
        assert result.tool_statuses.heuristics.status == "complete"
        assert result.tool_statuses.llm.status == "complete"
        assert result.tool_statuses.reputation.status == "complete"


class TestReputationIntegration:
    """Integration tests for the Safe Browsing reputation adapter wired into the orchestrator.

    All reputation calls use duck-typed stubs from conftest.py — no live network calls.
    """

    PHISHING_URL = "https://evil-phishing.example.com/login?token=steal"
    CLEAN_URL = "https://www.google.com/search?q=test"

    # -----------------------------------------------------------------------
    # 8. Reputation evidence affecting final classification
    # -----------------------------------------------------------------------

    def test_reputation_threat_promotes_classification_to_phishing(self, client):
        """When ThreatReputation returns high-severity evidence, classification becomes 'phishing'
        even when heuristics are clean and the LLM sees low risk.
        """
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.providers.gemini import GeminiAnalysisResult
        from backend.app.schemas.scan import ToolStatusDetail
        from backend.tests.conftest import ThreatReputation

        class LowRiskGemini:
            def analyze_target(self, **kwargs):
                return (
                    GeminiAnalysisResult(
                        classification="likely_legitimate",
                        risk_score=10,
                        reasons=["No obvious indicators."],
                        confidence_label="low",
                    ),
                    ToolStatusDetail(status="complete"),
                )

        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            gemini=LowRiskGemini(),
            reputation=ThreatReputation(),
        )
        try:
            response = client.post(
                "/api/v1/scans/website",
                json={"url": self.PHISHING_URL, "source": "manual_website"},
            )
            assert response.status_code == 200
            data = response.json()

            assert data["classification"] == "phishing"
            assert data["risk_score"] >= 70
            assert data["tool_statuses"]["reputation"]["status"] == "complete"
            assert data["analysis_status"] == "complete"

            rep_evidence = [e for e in data["evidence"] if e["source"] == "reputation"]
            assert len(rep_evidence) >= 1
            assert rep_evidence[0]["type"] == "reputation_threat"
            assert rep_evidence[0]["severity"] == "high"
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)

    def test_clean_reputation_with_heuristic_evidence_preserves_heuristic_score(self, client):
        """When reputation is clean, heuristic evidence still drives classification."""
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import ToolStatusDetail
        from backend.tests.conftest import CleanReputation

        deceptive_url = "https://paypal.com.phish-login.example.com/verify"
        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            gemini=type("UG", (), {"analyze_target": lambda s, **kw: (None, ToolStatusDetail(status="unavailable", reason_code="test_disabled"))})(),
            reputation=CleanReputation(),
        )
        try:
            response = client.post(
                "/api/v1/scans/website",
                json={"url": deceptive_url, "source": "manual_website"},
            )
            assert response.status_code == 200
            data = response.json()

            assert data["tool_statuses"]["reputation"]["status"] == "complete"
            assert data["classification"] in {"phishing", "suspicious"}
            rep_evidence = [e for e in data["evidence"] if e["source"] == "reputation"]
            assert rep_evidence == []
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)

    # -----------------------------------------------------------------------
    # 9. Provider failure — never produces falsely safe result
    # -----------------------------------------------------------------------

    def test_reputation_timeout_produces_partial_not_falsely_safe(self, client):
        """When reputation times out, analysis_status='partial' — never 'complete'."""
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.providers.gemini import GeminiAnalysisResult
        from backend.app.schemas.scan import ToolStatusDetail

        class TimingOutReputation:
            def check_reputation(self, **kwargs):
                return [], ToolStatusDetail(status="timeout", reason_code="request_timeout")

        class LowRiskGemini:
            def analyze_target(self, **kwargs):
                return (
                    GeminiAnalysisResult(
                        classification="likely_legitimate",
                        risk_score=5,
                        reasons=["Appears clean."],
                        confidence_label="low",
                    ),
                    ToolStatusDetail(status="complete"),
                )

        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            gemini=LowRiskGemini(),
            reputation=TimingOutReputation(),
        )
        try:
            response = client.post(
                "/api/v1/scans/website",
                json={"url": self.CLEAN_URL, "source": "manual_website"},
            )
            assert response.status_code == 200
            data = response.json()

            assert data["analysis_status"] == "partial"
            assert data["tool_statuses"]["reputation"]["status"] == "timeout"
            assert any("Reputation lookup timed out" in r for r in data["reasons"])
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)

    def test_provider_exception_produces_partial_not_crash(self, client):
        """When the reputation provider raises an unexpected exception, return partial safely."""
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.providers.gemini import GeminiAnalysisResult
        from backend.app.schemas.scan import ToolStatusDetail

        class ExplodingReputation:
            def check_reputation(self, **kwargs):
                raise RuntimeError("Unexpected provider crash")

        class LowRiskGemini:
            def analyze_target(self, **kwargs):
                return (
                    GeminiAnalysisResult(
                        classification="likely_legitimate",
                        risk_score=5,
                        reasons=["Appears clean."],
                        confidence_label="low",
                    ),
                    ToolStatusDetail(status="complete"),
                )

        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            gemini=LowRiskGemini(),
            reputation=ExplodingReputation(),
        )
        try:
            response = client.post(
                "/api/v1/scans/website",
                json={"url": self.CLEAN_URL, "source": "manual_website"},
            )
            assert response.status_code == 200
            data = response.json()

            assert data["analysis_status"] == "partial"
            assert data["tool_statuses"]["reputation"]["status"] == "error"
            assert data["tool_statuses"]["reputation"]["reason_code"] == "provider_exception"
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)

    # -----------------------------------------------------------------------
    # 10. Website endpoint — backward compatibility
    # -----------------------------------------------------------------------

    def test_website_endpoint_backward_compatible_without_reputation(self, client):
        """The default client fixture (no reputation key) must still return 200
        with provider_not_integrated."""
        response = client.post(
            "/api/v1/scans/website",
            json={"url": "https://example.com/login", "source": "manual_website"},
        )
        assert response.status_code == 200
        data = response.json()

        assert "scan_id" in data
        assert "tool_statuses" in data
        assert "reputation" in data["tool_statuses"]
        assert data["tool_statuses"]["reputation"]["status"] == "unavailable"
        assert data["tool_statuses"]["reputation"]["reason_code"] == "provider_not_integrated"

    def test_website_scan_with_complete_reputation_returns_complete_analysis(self, client):
        """When all providers complete, analysis_status must be 'complete'."""
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.providers.gemini import GeminiAnalysisResult
        from backend.app.schemas.scan import ToolStatusDetail
        from backend.tests.conftest import CleanReputation

        class CompleteGemini:
            def analyze_target(self, **kwargs):
                return (
                    GeminiAnalysisResult(
                        classification="likely_legitimate",
                        risk_score=5,
                        reasons=["Clean signals."],
                        confidence_label="high",
                    ),
                    ToolStatusDetail(status="complete"),
                )

        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            gemini=CompleteGemini(),
            reputation=CleanReputation(),
        )
        try:
            response = client.post(
                "/api/v1/scans/website",
                json={"url": self.CLEAN_URL, "source": "manual_website"},
            )
            assert response.status_code == 200
            data = response.json()

            assert data["analysis_status"] == "complete"
            assert data["tool_statuses"]["reputation"]["status"] == "complete"
            assert data["tool_statuses"]["llm"]["status"] == "complete"
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)
    def test_website_scan_skips_gemini_when_opted_out(self, client):
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.tests.conftest import CleanReputation

        class SpyGemini:
            def __init__(self):
                self.called = False

            def analyze_target(self, **kwargs):
                self.called = True
                raise AssertionError("Gemini should not be called")

        gemini = SpyGemini()

        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            gemini=gemini,
            reputation=CleanReputation(),
        )

        try:
            response = client.post(
                "/api/v1/scans/website",
                json={
                    "url": "https://example.com/login",
                    "source": "manual_website",
                    "opt_in_gemini": False,
                },
            )

            assert response.status_code == 200
            data = response.json()

            assert gemini.called is False
            assert data["tool_statuses"]["heuristics"]["status"] == "complete"
            assert data["tool_statuses"]["llm"]["status"] == "unavailable"
            assert data["tool_statuses"]["llm"]["reason_code"] == "opt_in_required"

        finally:
            app.dependency_overrides.pop(get_orchestrator, None)
    def test_website_scan_preserves_heuristics_when_gemini_times_out(self, client):
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import ToolStatusDetail
        from backend.tests.conftest import CleanReputation

        class TimingOutGemini:
            def analyze_target(self, **kwargs):
                return None, ToolStatusDetail(
                    status="timeout",
                    reason_code="request_timeout",
                )

        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            gemini=TimingOutGemini(),
            reputation=CleanReputation(),
        )

        try:
            response = client.post(
                "/api/v1/scans/website",
                json={
                    "url": "https://example.com/login",
                    "source": "manual_website",
                    "opt_in_gemini": True,
                },
            )

            assert response.status_code == 200
            data = response.json()

            assert data["tool_statuses"]["heuristics"]["status"] == "complete"
            assert data["tool_statuses"]["llm"]["status"] == "timeout"
            assert data["tool_statuses"]["llm"]["reason_code"] == "request_timeout"

        finally:
            app.dependency_overrides.pop(get_orchestrator, None)

    # -----------------------------------------------------------------------
    # 11. Email scans remain unchanged in Phase 1
    # -----------------------------------------------------------------------

    def test_email_scan_uses_provider_not_integrated_with_default_fixture(self, client):
        """Default client fixture has no reputation key; email scans must use
        provider_not_integrated — confirming email reputation is out of scope."""
        response = client.post(
            "/api/v1/scans/email",
            json={
                "sender": "noreply@legitimate.com",
                "subject": "Your account statement",
                "body_text": "Please find your statement attached.",
                "links": ["https://legitimate.com/statement"],
                "source": "gmail",
            },
        )
        assert response.status_code == 200
        data = response.json()

        assert data["tool_statuses"]["reputation"]["status"] == "unavailable"
        assert data["tool_statuses"]["reputation"]["reason_code"] == "provider_not_integrated"

    def test_email_scan_token_not_forwarded_to_reputation(self, client):
        """Phase 1: Email path must never forward full email link URLs with tokens
        to the reputation provider."""
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import ToolStatusDetail

        forwarded_urls: list[str] = []

        class RecordingReputation:
            def check_reputation(self, **kwargs):
                forwarded_urls.append(kwargs.get("url", ""))
                return [], ToolStatusDetail(status="complete")

        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            gemini=type("UG", (), {"analyze_target": lambda s, **kw: (None, ToolStatusDetail(status="unavailable", reason_code="test_disabled"))})(),
            reputation=RecordingReputation(),
        )
        try:
            response = client.post(
                "/api/v1/scans/email",
                json={
                    "sender": "phish@evil.com",
                    "subject": "Urgent: verify account",
                    "body_text": "Click now: https://evil.com/steal?token=abc",
                    "links": ["https://evil.com/steal?token=abc"],
                    "source": "gmail",
                },
            )
            assert response.status_code == 200
            for url in forwarded_urls:
                assert "token=abc" not in url, (
                    f"Sensitive email token was forwarded to reputation: {url}"
                )
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)

    def test_email_scan_never_invokes_reputation_adapter(self, client):
        """Phase 1: analyze_email must not invoke the reputation adapter even if configured."""
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import ToolStatusDetail

        class FailIfCalledReputation:
            def check_reputation(self, **kwargs):
                raise AssertionError("Email scan must not invoke reputation adapter in Phase 1")

        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            gemini=type("UG", (), {"analyze_target": lambda s, **kw: (None, ToolStatusDetail(status="unavailable", reason_code="test_disabled"))})(),
            reputation=FailIfCalledReputation(),
        )
        try:
            response = client.post(
                "/api/v1/scans/email",
                json={
                    "sender": "alert@bank.com",
                    "subject": "Statement Ready",
                    "body_text": "Please check your statement.",
                    "links": ["https://bank.com/statement"],
                    "source": "gmail",
                },
            )
            assert response.status_code == 200
            data = response.json()
            assert data["tool_statuses"]["reputation"]["status"] == "unavailable"
            assert data["tool_statuses"]["reputation"]["reason_code"] == "provider_not_integrated"
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)

    # -----------------------------------------------------------------------
    # Orchestrator unit: scoring invariants
    # -----------------------------------------------------------------------

    def test_reputation_threat_evidence_scores_at_or_above_phishing_threshold(self):
        """A single high-severity reputation EvidenceItem must produce score >= 70."""
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import EvidenceItem, ToolStatusDetail

        orch = RealDetectionOrchestrator()
        reputation_evidence = [
            EvidenceItem(
                type="reputation_threat",
                source="reputation",
                severity="high",
                explanation="Safe Browsing flagged as social engineering.",
            )
        ]

        result = orch._combine(
            evidence=[],
            llm_result=None,
            llm_status=ToolStatusDetail(status="unavailable", reason_code="test_disabled"),
            reputation_status=ToolStatusDetail(status="complete"),
            reputation_evidence=reputation_evidence,
        )

        assert result.risk_score is not None
        assert result.risk_score >= 70
        assert result.classification == "phishing"

    def test_score_clamped_to_100_with_many_evidence_items(self):
        """Score must not exceed 100 even with many high-severity evidence items."""
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.providers.gemini import GeminiAnalysisResult
        from backend.app.schemas.scan import EvidenceItem, ToolStatusDetail

        orch = RealDetectionOrchestrator()
        many_evidence = [
            EvidenceItem(
                type="reputation_threat",
                source="reputation",
                severity="high",
                explanation=f"Threat signal {i}.",
            )
            for i in range(20)
        ]

        result = orch._combine(
            evidence=[],
            llm_result=GeminiAnalysisResult(
                classification="phishing",
                risk_score=95,
                reasons=["Phishing detected."],
                confidence_label="high",
            ),
            llm_status=ToolStatusDetail(status="complete"),
            reputation_status=ToolStatusDetail(status="complete"),
            reputation_evidence=many_evidence,
        )

        assert result.risk_score is not None
        assert 0 <= result.risk_score <= 100

    def test_failed_lookup_produces_same_score_as_no_reputation(self):
        """When reputation fails, the risk score must be identical to no-reputation baseline."""
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.providers.gemini import GeminiAnalysisResult
        from backend.app.schemas.scan import ToolStatusDetail

        orch = RealDetectionOrchestrator()
        llm_result = GeminiAnalysisResult(
            classification="likely_legitimate",
            risk_score=5,
            reasons=["Clean."],
            confidence_label="low",
        )
        llm_status = ToolStatusDetail(status="complete")

        result_with_failure = orch._combine(
            evidence=[],
            llm_result=llm_result,
            llm_status=llm_status,
            reputation_status=ToolStatusDetail(status="timeout", reason_code="request_timeout"),
            reputation_evidence=[],
        )
        result_without_reputation = orch._combine(
            evidence=[],
            llm_result=llm_result,
            llm_status=llm_status,
            reputation_status=ToolStatusDetail(
                status="unavailable", reason_code="provider_not_integrated"
            ),
            reputation_evidence=[],
        )

        assert result_with_failure.risk_score == result_without_reputation.risk_score
        assert result_with_failure.classification == result_without_reputation.classification

    # -----------------------------------------------------------------------
    # Privacy & Gemini email integration tests
    # -----------------------------------------------------------------------

    def test_email_scan_gemini_opt_in_explicit_false(self, client):
        """Explicit opt_in_gemini=False must not call Gemini."""
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator

        class ExplodingGemini:
            def analyze_target(self, **kwargs):
                raise AssertionError("Gemini must not be called when opt_in_gemini=False")

        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            gemini=ExplodingGemini(),
        )
        try:
            resp = client.post(
                "/api/v1/scans/email",
                json={
                    "sender": "alerts@service.com",
                    "subject": "Security notice",
                    "body_text": "Please check your account.",
                    "links": ["https://service.com/account"],
                    "source": "gmail",
                    "opt_in_gemini": False,
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["tool_statuses"]["llm"]["status"] == "unavailable"
            assert data["tool_statuses"]["llm"]["reason_code"] == "opt_in_required"
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)

    def test_email_scan_gemini_opt_in_explicit_true_invokes_gemini(self, client):
        """Explicit opt_in_gemini=True invokes Gemini and sanitizes persisted reasons."""
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.providers.gemini import GeminiAnalysisResult
        from backend.app.schemas.scan import ToolStatusDetail

        class SpyGemini:
            def __init__(self):
                self.called = False

            def analyze_target(self, **kwargs):
                self.called = True
                return (
                    GeminiAnalysisResult(
                        classification="phishing",
                        risk_score=85,
                        reasons=["Model saw raw user body: SensitiveSecret123 in email."],
                        confidence_label="high",
                    ),
                    ToolStatusDetail(status="complete"),
                )

        gemini_spy = SpyGemini()
        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            gemini=gemini_spy,
        )
        try:
            resp = client.post(
                "/api/v1/scans/email",
                json={
                    "sender": "secret-sender@service.com",
                    "subject": "Very Secret Subject",
                    "body_text": "Here is SensitiveSecret123 in body.",
                    "links": ["https://service.com/login"],
                    "source": "gmail",
                    "opt_in_gemini": True,
                },
            )
            assert resp.status_code == 200
            assert gemini_spy.called is True
            data = resp.json()
            # Verify classification and score were updated by Gemini
            assert data["classification"] == "phishing"
            assert data["risk_score"] == 85
            # Verify sensitive content from raw LLM reason is NOT persisted
            reasons_text = " ".join(data["reasons"])
            assert "SensitiveSecret123" not in reasons_text
            assert "Very Secret Subject" not in reasons_text
            assert "secret-sender@service.com" not in reasons_text
            assert any("AI content analysis detected patterns" in r for r in data["reasons"])
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)

    def test_email_scan_gemini_reasons_and_evidence_do_not_contain_raw_email_text(self, client):
        """Gemini-generated reasons containing sensitive email content must be replaced
        with static templates.  Raw LLM evidence cannot enter the persisted evidence list
        because GeminiAnalysisResult has no evidence field; this test verifies both
        that raw LLM reason strings are stripped and that the evidence list contains
        only deterministic heuristic findings with static explanations."""
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.providers.gemini import GeminiAnalysisResult
        from backend.app.schemas.scan import ToolStatusDetail

        SENSITIVE_BODY = "PRIVATE_BODY_CONTENT_DO_NOT_PERSIST"
        SENSITIVE_SUBJECT = "PRIVATE_SUBJECT_DO_NOT_PERSIST"
        SENSITIVE_SENDER = "private-sender-do-not-persist@secret.example.com"
        SENSITIVE_LLM_REASON = (
            f"The email body '{SENSITIVE_BODY}' from {SENSITIVE_SENDER} with "
            f"subject '{SENSITIVE_SUBJECT}' is a phishing attempt."
        )

        class SensitiveGemini:
            """Returns a result that embeds raw email content in its reason strings."""
            def analyze_target(self, **kwargs):
                return (
                    GeminiAnalysisResult(
                        classification="phishing",
                        risk_score=90,
                        reasons=[SENSITIVE_LLM_REASON],
                        confidence_label="high",
                    ),
                    ToolStatusDetail(status="complete"),
                )

        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            gemini=SensitiveGemini(),
        )
        try:
            resp = client.post(
                "/api/v1/scans/email",
                json={
                    "sender": SENSITIVE_SENDER,
                    "subject": SENSITIVE_SUBJECT,
                    "body_text": SENSITIVE_BODY,
                    "links": ["https://evil.example.com/login"],
                    "source": "gmail",
                    "opt_in_gemini": True,
                },
            )
            assert resp.status_code == 200
            data = resp.json()

            # Classification and score from Gemini should be honoured
            assert data["classification"] == "phishing"
            assert data["risk_score"] == 90

            # Build a combined blob of all persisted text for easy searching
            all_text = " ".join(data["reasons"])
            all_text += " ".join(
                item["explanation"] for item in data["evidence"]
            )

            # Sensitive content from raw LLM reason must NOT appear anywhere
            assert SENSITIVE_BODY not in all_text, (
                "Raw email body content found in persisted scan data"
            )
            assert SENSITIVE_SUBJECT not in all_text, (
                "Raw email subject found in persisted scan data"
            )
            assert SENSITIVE_SENDER not in all_text, (
                "Raw sender address found in persisted scan data"
            )
            assert SENSITIVE_LLM_REASON not in all_text, (
                "Verbatim LLM reason string found in persisted scan data"
            )

            # Static sanitized template must be present
            assert any(
                "AI content analysis detected patterns" in r for r in data["reasons"]
            ), "Expected sanitized Gemini reason template not found"

            # Evidence explanations must all be static deterministic strings
            for item in data["evidence"]:
                assert SENSITIVE_BODY not in item["explanation"]
                assert SENSITIVE_SUBJECT not in item["explanation"]
                assert SENSITIVE_SENDER not in item["explanation"]
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)

    def test_email_scan_gemini_failure_does_not_produce_false_safe_classification(self, client):
        """When Gemini fails on an email scan with suspicious heuristic indicators,
        it must not downgrade to likely_legitimate.
        """
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import ToolStatusDetail

        class FailingGemini:
            def analyze_target(self, **kwargs):
                return None, ToolStatusDetail(status="error", reason_code="http_500")

        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            gemini=FailingGemini(),
        )
        try:
            resp = client.post(
                "/api/v1/scans/email",
                json={
                    "sender": "alert@phish.com",
                    "subject": "Urgent: Account Suspended",
                    "body_text": "Your account has been suspended! Immediate action is required.",
                    "links": ["https://192.168.1.1/login"],
                    "source": "gmail",
                    "opt_in_gemini": True,
                },
            )
            assert resp.status_code == 200
            data = resp.json()
            assert data["classification"] in ("phishing", "suspicious")
            assert data["classification"] != "likely_legitimate"
            assert data["tool_statuses"]["llm"]["status"] == "error"
            assert data["analysis_status"] == "partial"
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)


class TestEmailScanScoringAndPartialAnalysisRegression:
    """
    Regression tests for the false-positive and partial-analysis messaging issues
    identified in the Gmail phishing scan audit.

    Background: A legitimate Google transactional email containing a 284-character
    link produced:
    - classification: suspicious
    - risk_score: 60
    - analysis_status: partial
    - evidence: url_excessive_length (medium, 50 pts) + deep_subdomain_nesting
      (medium) + excessive_hyphens (low) → score = 50 + 10 = 60.

    Root causes:
    1. url_excessive_length and deep_subdomain_nesting were 'medium' severity,
       inflating the score when multiple correlated structural signals fire from
       one URL. Both are now 'low' — 25 pts base, capped bonus.
    2. opt_in_required Gemini status was classified as a runtime failure in the
       UI, causing the partial-analysis banner to say 'Some checks could not
       finish due to a service timeout or error' — wrong for an intentional gate.
    """

    def test_email_scan_long_link_does_not_produce_excessive_risk_score(self, client):
        """An email with a single long (> 100 char) link that is otherwise structurally
        clean must NOT score above 35. url_excessive_length alone (low, 25 pts) or
        combined with other low-severity structural signals must not reach 60."""
        payload = {
            "sender": "no-reply@google.com",
            "subject": "Set up your Google account",
            "body_text": "Click the link to complete account setup.",
            "links": [
                "https://accounts.google.com/o/oauth2/auth"
                "?client_id=1234567890"
                "&redirect_uri=https%3A%2F%2Fmail.google.com%2Foauth2%2Fcallback"
                "&response_type=code&scope=openid+email+profile"
                "&state=CSRF_TOKEN_PLACEHOLDER_xyzxyzxyz"
                "&nonce=NONCE_VALUE_abcdefghijklmnopqrstuvwxyz"
                "&prompt=select_account"
            ],
            "source": "gmail",
        }
        response = client.post("/api/v1/scans/email", json=payload)
        assert response.status_code == 200
        data = response.json()

        if data["risk_score"] is not None:
            assert data["risk_score"] <= 35, (
                f"Long legitimate link scored {data['risk_score']} — "
                "correlated structural signals must not exceed 35."
            )

    def test_email_scan_opt_in_disabled_produces_correct_tool_status(self, client):
        """With Gemini opt-in disabled (default), tool_statuses.llm must have
        status=unavailable and reason_code=opt_in_required. This state is
        intentional and must not be reported as a service crash."""
        payload = {
            "sender": "no-reply@google.com",
            "subject": "Security notice",
            "body_text": "Review your account activity.",
            "source": "gmail",
        }
        response = client.post("/api/v1/scans/email", json=payload)
        assert response.status_code == 200
        data = response.json()

        llm_status = data["tool_statuses"]["llm"]
        assert llm_status["status"] == "unavailable"
        assert llm_status["reason_code"] == "opt_in_required", (
            "Gemini opt-in disabled must report reason_code='opt_in_required', "
            "not a timeout or error code."
        )

    def test_email_scan_reputation_unintegrated_produces_correct_tool_status(self, client):
        """Email scans must always report reputation as provider_not_integrated,
        not as timeout or error."""
        payload = {
            "sender": "no-reply@google.com",
            "subject": "Security notice",
            "body_text": "Review your account.",
            "source": "gmail",
        }
        response = client.post("/api/v1/scans/email", json=payload)
        assert response.status_code == 200
        data = response.json()

        rep_status = data["tool_statuses"]["reputation"]
        assert rep_status["status"] == "unavailable"
        assert rep_status["reason_code"] == "provider_not_integrated", (
            "Email scan reputation must be provider_not_integrated — "
            "email reputation is out of scope, not a runtime failure."
        )

    def test_email_scan_long_url_evidence_severity_is_low(self, client):
        """The url_excessive_length evidence item must carry severity='low'.
        Verifies that the heuristic severity downgrade is applied end-to-end."""
        long_link = (
            "https://email.company.com/unsubscribe"
            "?token=a1b2c3d4-e5f6-7890-abcd-ef1234567890"
            "&list=newsletter&user=encoded_id_123456"
            "&sig=HMAC_SIGNATURE_VALUE_PLACEHOLDER_abcdef"
        )
        assert len(long_link) > 100

        payload = {
            "sender": "newsletter@company.com",
            "subject": "Your weekly digest",
            "body_text": "Unsubscribe from this list.",
            "links": [long_link],
            "source": "gmail",
        }
        response = client.post("/api/v1/scans/email", json=payload)
        assert response.status_code == 200
        data = response.json()

        length_evidence = [
            e for e in data["evidence"] if e["type"] == "url_excessive_length"
        ]
        for item in length_evidence:
            assert item["severity"] == "low", (
                f"url_excessive_length severity must be 'low' in API response, "
                f"got '{item['severity']}'."
            )

    def test_email_scan_deep_subdomain_nesting_severity_is_low(self, client):
        """The deep_subdomain_nesting evidence item must carry severity='low'.
        Verifies end-to-end that the severity downgrade takes effect."""
        link_with_deep_nesting = "https://login.secure.verify.accounts.example.com/auth?token=abc"

        payload = {
            "sender": "alerts@example.com",
            "subject": "Account verification",
            "body_text": "Please click the link.",
            "links": [link_with_deep_nesting],
            "source": "gmail",
        }
        response = client.post("/api/v1/scans/email", json=payload)
        assert response.status_code == 200
        data = response.json()

        nesting_evidence = [
            e for e in data["evidence"] if e["type"] == "deep_subdomain_nesting"
        ]
        for item in nesting_evidence:
            assert item["severity"] == "low", (
                f"deep_subdomain_nesting severity must be 'low', got '{item['severity']}'."
            )

    def test_website_scan_misleading_subdomain_still_reaches_phishing_threshold(self, client):
        """Website scanning behavior must be unaffected. A misleading subdomain
        still scores >= 70 and classifies as phishing."""
        payload = {
            "url": "https://paypal.com.account-secure-verify.phish-test.xyz/login",
            "source": "manual_website",
        }
        response = client.post("/api/v1/scans/website", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["classification"] == "phishing", (
            "misleading_subdomain must still classify as phishing for website scans."
        )
        assert data["risk_score"] is not None
        assert data["risk_score"] >= 70, (
            f"misleading_subdomain must score >= 70, got {data['risk_score']}."
        )
        assert any(
            e["type"] == "misleading_subdomain" for e in data["evidence"]
        )

    def test_website_scan_clean_url_unaffected(self, client):
        """Clean website scans produce no evidence (unchanged behavior)."""
        payload = {
            "url": "https://en.wikipedia.org/wiki/Computer_security",
            "source": "auto_website",
        }
        response = client.post("/api/v1/scans/website", json=payload)
        assert response.status_code == 200
        data = response.json()
        # Clean domain should produce no heuristic evidence
        heuristic_evidence = [e for e in data["evidence"] if e["source"] == "heuristics"]
        assert heuristic_evidence == [], (
            f"Clean Wikipedia URL must produce no heuristic evidence, got {heuristic_evidence}"
        )

    def test_clean_email_scan_returns_partial_status_with_null_classification_and_score(self, client):
        """A clean email scan with 0 heuristic findings and external providers skipped
        (Gemini opt-in required, reputation unintegrated) must return:
        - HTTP 200
        - analysis_status="partial" (NOT "unavailable")
        - classification=None (NOT likely_legitimate)
        - risk_score=None (NOT 0)
        - heuristics tool status="complete"
        - llm status="unavailable" with reason_code="opt_in_required"
        - reputation status="unavailable" with reason_code="provider_not_integrated"
        - reason clarifying that deterministic heuristics completed without finding suspicious indicators.
        """
        payload = {
            "sender": "no-reply@google.com",
            "subject": "Test of phishing detection",
            "body_text": "This email is for test purpose only",
            "source": "gmail",
        }
        response = client.post("/api/v1/scans/email", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["analysis_status"] == "partial", (
            f"Expected analysis_status='partial', got '{data['analysis_status']}'"
        )
        assert data["classification"] is None, (
            f"Expected classification=None, got {data['classification']}"
        )
        assert data["risk_score"] is None, (
            f"Expected risk_score=None, got {data['risk_score']}"
        )
        assert data["evidence"] == []

        tool_statuses = data["tool_statuses"]
        assert tool_statuses["heuristics"]["status"] == "complete"
        assert tool_statuses["llm"]["status"] == "unavailable"
        assert tool_statuses["llm"]["reason_code"] == "opt_in_required"
        assert tool_statuses["reputation"]["status"] == "unavailable"
        assert tool_statuses["reputation"]["reason_code"] == "provider_not_integrated"

        assert any(
            "Deterministic heuristics completed without finding suspicious indicators" in r
            for r in data["reasons"]
        ), f"Expected clean heuristics explanation in reasons: {data['reasons']}"
        assert any(
            "AI content analysis is disabled" in r or "External AI analysis is disabled" in r
            for r in data["reasons"]
        )

    def test_clean_email_scan_with_gemini_opt_in_enabled_returns_likely_legitimate(self, client):
        """When Gemini is explicitly opted into and returns likely_legitimate with score 10,
        the email scan returns likely_legitimate with score 10 and analysis_status='partial'
        (since reputation is unintegrated).
        """
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.providers.gemini import GeminiAnalysisResult
        from backend.app.schemas.scan import ToolStatusDetail

        class CleanEmailGemini:
            def analyze_target(self, **kwargs):
                return (
                    GeminiAnalysisResult(
                        classification="likely_legitimate",
                        risk_score=10,
                        reasons=["Email body appears normal and transactional."],
                        confidence_label="low",
                    ),
                    ToolStatusDetail(status="complete"),
                )

        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            gemini=CleanEmailGemini()
        )
        try:
            payload = {
                "sender": "no-reply@google.com",
                "subject": "Test of phishing detection",
                "body_text": "This email is for test purpose only",
                "source": "gmail",
                "opt_in_gemini": True,
            }
            response = client.post("/api/v1/scans/email", json=payload)
            assert response.status_code == 200
            data = response.json()

            assert data["classification"] == "likely_legitimate"
            assert data["risk_score"] == 10
            assert data["analysis_status"] == "partial"
            assert data["tool_statuses"]["llm"]["status"] == "complete"
            assert data["tool_statuses"]["heuristics"]["status"] == "complete"
            assert data["tool_statuses"]["reputation"]["status"] == "unavailable"
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)

    def test_email_scan_heuristics_exception_returns_unavailable_status(self, client):
        """When the heuristics engine raises an unhandled exception, the scan must return
        analysis_status='unavailable', classification=None, risk_score=None, and
        heuristics tool status='error'.
        """
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator

        class CrashingHeuristicsEngine:
            def analyze_email(self, **kwargs):
                raise RuntimeError("Unexpected failure in heuristics engine")

        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            heuristics=CrashingHeuristicsEngine()
        )
        try:
            payload = {
                "sender": "no-reply@google.com",
                "subject": "Test notice",
                "body_text": "Content",
                "source": "gmail",
            }
            response = client.post("/api/v1/scans/email", json=payload)
            assert response.status_code == 200
            data = response.json()

            assert data["analysis_status"] == "unavailable"
            assert data["classification"] is None
            assert data["risk_score"] is None
            assert data["tool_statuses"]["heuristics"]["status"] == "error"
            assert data["tool_statuses"]["heuristics"]["reason_code"] == "heuristics_exception"
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)

    def test_email_scan_gemini_timeout_with_clean_heuristics_returns_unavailable(self, client):
        """When Gemini is enabled but times out, and heuristics found 0 indicators,
        the scan must return analysis_status='unavailable' (not partial or likely_legitimate).
        """
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import ToolStatusDetail

        class TimingOutGemini:
            def analyze_target(self, **kwargs):
                return (
                    None,
                    ToolStatusDetail(
                        status="timeout",
                        reason_code="request_timeout",
                    ),
                )

        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            gemini=TimingOutGemini()
        )
        try:
            payload = {
                "sender": "no-reply@google.com",
                "subject": "Clean email",
                "body_text": "Clean body",
                "source": "gmail",
                "opt_in_gemini": True,
            }
            response = client.post("/api/v1/scans/email", json=payload)
            assert response.status_code == 200
            data = response.json()

            assert data["analysis_status"] == "unavailable"
            assert data["classification"] is None
            assert data["risk_score"] is None
            assert data["tool_statuses"]["llm"]["status"] == "timeout"
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)

    def test_email_scan_gemini_error_with_clean_heuristics_returns_unavailable(self, client):
        """When Gemini returns an error and heuristics found 0 indicators,
        the scan must return analysis_status='unavailable'.
        """
        from backend.app.api.v1.scans import get_orchestrator
        from backend.app.detection.orchestrator import RealDetectionOrchestrator
        from backend.app.schemas.scan import ToolStatusDetail

        class FailingGemini:
            def analyze_target(self, **kwargs):
                return (
                    None,
                    ToolStatusDetail(
                        status="error",
                        reason_code="internal_provider_error",
                    ),
                )

        app.dependency_overrides[get_orchestrator] = lambda: RealDetectionOrchestrator(
            gemini=FailingGemini()
        )
        try:
            payload = {
                "sender": "no-reply@google.com",
                "subject": "Clean email",
                "body_text": "Clean body",
                "source": "gmail",
                "opt_in_gemini": True,
            }
            response = client.post("/api/v1/scans/email", json=payload)
            assert response.status_code == 200
            data = response.json()

            assert data["analysis_status"] == "unavailable"
            assert data["classification"] is None
            assert data["risk_score"] is None
            assert data["tool_statuses"]["llm"]["status"] == "error"
        finally:
            app.dependency_overrides.pop(get_orchestrator, None)

    def test_reputation_unavailable_alone_does_not_cause_unavailable_with_heuristic_evidence(self, client):
        """When heuristics detects suspicious indicators in an email, the scan returns
        analysis_status='partial' (due to unintegrated reputation), NOT 'unavailable'.
        """
        payload = {
            "sender": "security@alert-paypal.com",
            "subject": "Account suspension warning",
            "body_text": "Please verify your account immediately.",
            "links": ["https://paypal.com.verify-account.phish-test.xyz/login"],
            "source": "gmail",
        }
        response = client.post("/api/v1/scans/email", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["analysis_status"] == "partial"
        assert data["classification"] in ("suspicious", "phishing")
        assert data["risk_score"] is not None and data["risk_score"] >= 40
        assert data["tool_statuses"]["reputation"]["status"] == "unavailable"

    def test_email_scan_multiple_long_urls_deduplicates_scoring_and_evidence(self, client):
        """A legitimate email (such as Meetup) containing multiple long URLs must
        produce a single consolidated url_excessive_length evidence item and score 25/100,
        not inflating to 45/100 due to repeated instances of the same heuristic."""
        long_meetup_links = [
            f"https://www.meetup.com/ny-tech-meetup/events/rsvp?token=PRIV_TOKEN_{i}_abcdef123456&source=digest&sig=SIGNATURE_{i}_xyz"
            for i in range(5)
        ]
        for link in long_meetup_links:
            assert len(link) > 100

        payload = {
            "sender": "events@meetup.com",
            "subject": "Upcoming tech meetups this week",
            "body_text": "Join us for great conversations and presentations.",
            "links": long_meetup_links,
            "source": "gmail",
        }
        response = client.post("/api/v1/scans/email", json=payload)
        assert response.status_code == 200
        data = response.json()

        # Score must be 25 (NOT 45)
        assert data["risk_score"] == 25, (
            f"5 long URLs inflated risk score to {data['risk_score']} — expected 25."
        )
        assert data["classification"] == "suspicious"
        assert data["analysis_status"] == "partial"

        # Evidence must contain exactly 1 consolidated url_excessive_length item
        length_items = [e for e in data["evidence"] if e["type"] == "url_excessive_length"]
        assert len(length_items) == 1, (
            f"Expected exactly 1 url_excessive_length finding, got {len(length_items)}"
        )
        item = length_items[0]
        assert "5 links in this email exceed 100 characters in length" in item["explanation"]
        assert "longest is" in item["explanation"]

        # Privacy verification: No sensitive tokens, usernames, or raw URLs in explanation
        for i in range(5):
            assert f"PRIV_TOKEN_{i}" not in item["explanation"]
            assert f"SIGNATURE_{i}" not in item["explanation"]
        assert "https://" not in item["explanation"]

        # Reasons list must contain no duplicate strings
        assert len(data["reasons"]) == len(set(data["reasons"])), (
            f"data['reasons'] contains duplicate strings: {data['reasons']}"
        )

    def test_email_scan_ten_long_urls_produces_identical_score_to_single_long_url(self, client):
        """Ten long URLs must not produce a higher score than one long URL."""
        one_link_payload = {
            "sender": "info@example.com",
            "subject": "Notice",
            "body_text": "Click here.",
            "links": [
                "https://www.example.com/very/long/tracking/url/with/lots/of/parameters/to/reach/length/above/one/hundred/characters?tracking_id=12345"
            ],
            "source": "gmail",
        }
        resp1 = client.post("/api/v1/scans/email", json=one_link_payload)
        assert resp1.status_code == 200
        score_1 = resp1.json()["risk_score"]
        assert score_1 == 25

        ten_links_payload = {
            "sender": "info@example.com",
            "subject": "Notice",
            "body_text": "Click here.",
            "links": [
                f"https://www.example.com/very/long/tracking/url/with/lots/of/parameters/to/reach/length/above/one/hundred/characters?tracking_id=12345_{i}"
                for i in range(10)
            ],
            "source": "gmail",
        }
        resp10 = client.post("/api/v1/scans/email", json=ten_links_payload)
        assert resp10.status_code == 200
        score_10 = resp10.json()["risk_score"]
        assert score_10 == 25, (
            f"Ten long URLs scored {score_10}, expected identical score to 1 URL ({score_1})"
        )

    def test_email_scan_multiple_long_urls_with_phishing_link_maintains_phishing_verdict(self, client):
        """When multiple long URLs are accompanied by an independent high-confidence
        indicator (misleading_subdomain), the high-severity finding retains its full weight
        and reaches phishing classification (>= 70)."""
        links = [
            f"https://www.legitimate-service.com/tracking/path/with/long/parameters?param={i}_{'x'*80}"
            for i in range(5)
        ] + ["https://paypal.com.verify-login.evil-phish.xyz/account"]

        payload = {
            "sender": "alerts@security-notice.com",
            "subject": "Account alert",
            "body_text": "Verify your account immediately.",
            "links": links,
            "source": "gmail",
        }
        response = client.post("/api/v1/scans/email", json=payload)
        assert response.status_code == 200
        data = response.json()

        assert data["classification"] == "phishing"
        assert data["risk_score"] is not None
        assert data["risk_score"] >= 70
        # High base (75) + 2 extra independent categories (url_excessive_length + deep_subdomain_nesting) * 5 = 85
        assert data["risk_score"] == 85
        evidence_types = {e["type"] for e in data["evidence"]}
        assert "misleading_subdomain" in evidence_types
        assert "url_excessive_length" in evidence_types
        assert "deep_subdomain_nesting" in evidence_types
