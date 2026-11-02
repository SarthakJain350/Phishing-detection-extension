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
                return {"reputation": "clean"}, ToolStatusDetail(status="complete")

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
