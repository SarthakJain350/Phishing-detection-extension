"""Unit tests for the Google Safe Browsing adapter.

All HTTP calls are mocked — no live network requests are made.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import httpx
import pytest

from backend.app.providers.safe_browsing import SafeBrowsingAdapter
from backend.app.schemas.scan import EvidenceItem, ToolStatusDetail


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_adapter(api_key: str | None = "test-api-key") -> SafeBrowsingAdapter:
    """Create a SafeBrowsingAdapter with the given API key injected."""
    adapter = SafeBrowsingAdapter.__new__(SafeBrowsingAdapter)
    adapter._api_key = api_key
    return adapter


def _mock_response(body: dict | str, status_code: int = 200) -> httpx.Response:
    """Build a synthetic httpx.Response without a real HTTP connection."""
    if isinstance(body, dict):
        content = json.dumps(body).encode()
    else:
        content = body.encode()
    return httpx.Response(
        status_code=status_code,
        content=content,
        headers={"Content-Type": "application/json"},
    )


def _social_engineering_matches_body() -> dict:
    return {
        "matches": [
            {
                "threatType": "SOCIAL_ENGINEERING",
                "platformType": "ANY_PLATFORM",
                "threat": {"url": "https://evil-phishing.example.com/login"},
                "cacheDuration": "300s",
                "threatEntryType": "URL",
            }
        ]
    }


# ---------------------------------------------------------------------------
# 1. Missing API key / disabled feature
# ---------------------------------------------------------------------------

class TestMissingApiKey:
    def test_no_api_key_returns_unavailable_no_api_key(self):
        """When SAFE_BROWSING_API_KEY is not set, return unavailable/no_api_key immediately."""
        adapter = _make_adapter(api_key=None)
        evidence, status = adapter.check_reputation(
            target_reference="example.com",
            url="https://example.com/page",
        )
        assert evidence == []
        assert status.status == "unavailable"
        assert status.reason_code == "no_api_key"

    def test_empty_string_key_treated_as_absent(self):
        """An empty string key must behave the same as a missing key."""
        adapter = _make_adapter(api_key="")
        evidence, status = adapter.check_reputation(
            target_reference="example.com",
            url="https://example.com/page",
        )
        assert evidence == []
        assert status.status == "unavailable"
        assert status.reason_code == "no_api_key"

    def test_disabled_feature_never_returns_complete(self):
        """The feature disabled state must never yield status='complete'."""
        adapter = _make_adapter(api_key=None)
        _, status = adapter.check_reputation(
            target_reference="evil.com",
            url="https://evil.com/phish",
        )
        assert status.status != "complete"


# ---------------------------------------------------------------------------
# 2. Successful lookup — no threats found
# ---------------------------------------------------------------------------

class TestSuccessfulLookupClean:
    def test_empty_object_response_means_clean(self):
        """Safe Browsing returns {} when no threats are found — must map to complete/empty."""
        adapter = _make_adapter()
        mock_resp = _mock_response({})

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="google.com",
                url="https://www.google.com/search?q=test",
            )

        assert evidence == []
        assert status.status == "complete"
        assert status.reason_code is None

    def test_empty_matches_list_means_clean(self):
        """matches: [] also means no threats — complete with empty evidence."""
        adapter = _make_adapter()
        mock_resp = _mock_response({"matches": []})

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="google.com",
                url="https://www.google.com/",
            )

        assert evidence == []
        assert status.status == "complete"

    def test_no_threats_never_implies_safe_classification(self):
        """A clean Safe Browsing result must return empty evidence — not a 'safe' verdict."""
        adapter = _make_adapter()
        mock_resp = _mock_response({})

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="target.com",
                url="https://target.com/page",
            )

        # Adapter returns evidence only, never a classification
        assert isinstance(evidence, list)
        assert status.status == "complete"


# ---------------------------------------------------------------------------
# 3. Confirmed phishing / social-engineering match
# ---------------------------------------------------------------------------

class TestThreatDetected:
    def test_social_engineering_match_returns_high_severity_evidence(self):
        """A SOCIAL_ENGINEERING match must produce an EvidenceItem with severity='high'."""
        adapter = _make_adapter()
        mock_resp = _mock_response(_social_engineering_matches_body())

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="evil-phishing.example.com",
                url="https://evil-phishing.example.com/login",
            )

        assert status.status == "complete"
        assert len(evidence) == 1
        item = evidence[0]
        assert isinstance(item, EvidenceItem)
        assert item.type == "reputation_threat"
        assert item.source == "reputation"
        assert item.severity == "high"
        assert "social engineering" in item.explanation.lower()

    def test_malware_match_returns_high_severity_evidence(self):
        """A MALWARE match must produce high severity evidence."""
        adapter = _make_adapter()
        mock_resp = _mock_response({
            "matches": [{"threatType": "MALWARE", "platformType": "ANY_PLATFORM"}]
        })

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="malware-host.com",
                url="https://malware-host.com/download",
            )

        assert status.status == "complete"
        assert len(evidence) == 1
        assert evidence[0].severity == "high"
        assert "malware" in evidence[0].explanation.lower()

    def test_unwanted_software_match_returns_medium_severity(self):
        """An UNWANTED_SOFTWARE match must produce medium severity evidence."""
        adapter = _make_adapter()
        mock_resp = _mock_response({
            "matches": [{"threatType": "UNWANTED_SOFTWARE", "platformType": "ANY_PLATFORM"}]
        })

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="pup-host.com",
                url="https://pup-host.com/install",
            )

        assert status.status == "complete"
        assert evidence[0].severity == "medium"

    def test_duplicate_threat_types_deduplicated(self):
        """Multiple matches of the same threat type produce only one EvidenceItem."""
        adapter = _make_adapter()
        mock_resp = _mock_response({
            "matches": [
                {"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM"},
                {"threatType": "SOCIAL_ENGINEERING", "platformType": "WINDOWS"},
            ]
        })

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="evil.com",
                url="https://evil.com/phish",
            )

        assert status.status == "complete"
        assert len(evidence) == 1

    def test_multiple_distinct_threat_types_produce_multiple_evidence(self):
        """Two distinct threat types produce two distinct EvidenceItems."""
        adapter = _make_adapter()
        mock_resp = _mock_response({
            "matches": [
                {"threatType": "SOCIAL_ENGINEERING", "platformType": "ANY_PLATFORM"},
                {"threatType": "MALWARE", "platformType": "ANY_PLATFORM"},
            ]
        })

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="evil.com",
                url="https://evil.com/payload",
            )

        assert status.status == "complete"
        assert len(evidence) == 2
        evidence_types = {e.type for e in evidence}
        assert evidence_types == {"reputation_threat"}

    def test_threat_match_evidence_items_are_valid_schema(self):
        """All evidence items from threat matches must satisfy the EvidenceItem schema."""
        adapter = _make_adapter()
        mock_resp = _mock_response(_social_engineering_matches_body())

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, _ = adapter.check_reputation(
                target_reference="evil.com",
                url="https://evil.com/phish",
            )

        for item in evidence:
            assert item.type and isinstance(item.type, str)
            assert item.source == "reputation"
            assert item.severity in {"low", "medium", "high"}
            assert item.explanation and isinstance(item.explanation, str)


# ---------------------------------------------------------------------------
# 4. Timeout and network failure
# ---------------------------------------------------------------------------

class TestTimeoutAndNetworkFailure:
    def test_timeout_returns_timeout_status(self):
        """An httpx.TimeoutException must map to status='timeout', reason='request_timeout'."""
        adapter = _make_adapter()

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = httpx.TimeoutException("Request timed out")
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="slow.com",
                url="https://slow.com/page",
            )

        assert evidence == []
        assert status.status == "timeout"
        assert status.reason_code == "request_timeout"

    def test_network_error_returns_unavailable_transport_error(self):
        """An httpx.HTTPError (e.g. connection refused) maps to status='unavailable'."""
        adapter = _make_adapter()

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = httpx.ConnectError("Connection refused")
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="unreachable.com",
                url="https://unreachable.com/",
            )

        assert evidence == []
        assert status.status == "unavailable"
        assert status.reason_code == "http_transport_error"

    def test_timeout_never_returns_complete(self):
        """A timeout must never produce status='complete', which would imply clean."""
        adapter = _make_adapter()

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = httpx.TimeoutException("timeout")
            mock_client_cls.return_value = mock_client

            _, status = adapter.check_reputation(
                target_reference="example.com",
                url="https://example.com/",
            )

        assert status.status != "complete"

    def test_network_failure_never_returns_complete(self):
        """A transport error must never produce status='complete'."""
        adapter = _make_adapter()

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = httpx.ConnectError("refused")
            mock_client_cls.return_value = mock_client

            _, status = adapter.check_reputation(
                target_reference="example.com",
                url="https://example.com/",
            )

        assert status.status != "complete"


# ---------------------------------------------------------------------------
# 5. Rate limiting and server errors
# ---------------------------------------------------------------------------

class TestRateLimitAndServerErrors:
    def test_http_429_returns_unavailable_rate_limited(self):
        """HTTP 429 from Safe Browsing must map to status='unavailable', reason='rate_limited'."""
        adapter = _make_adapter()
        mock_resp = _mock_response({"error": "rate limit exceeded"}, status_code=429)

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="popular.com",
                url="https://popular.com/page",
            )

        assert evidence == []
        assert status.status == "unavailable"
        assert status.reason_code == "rate_limited"

    def test_http_500_returns_error(self):
        """HTTP 500 from Safe Browsing must map to status='error', reason='http_500'."""
        adapter = _make_adapter()
        mock_resp = _mock_response({"error": "internal server error"}, status_code=500)

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="example.com",
                url="https://example.com/page",
            )

        assert evidence == []
        assert status.status == "error"
        assert status.reason_code == "http_500"

    def test_http_503_returns_error(self):
        """HTTP 503 (service unavailable) must map to status='error', reason='http_503'."""
        adapter = _make_adapter()
        mock_resp = _mock_response({}, status_code=503)

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="down.com",
                url="https://down.com/",
            )

        assert evidence == []
        assert status.status == "error"
        assert status.reason_code == "http_503"

    def test_rate_limit_never_returns_complete(self):
        """Rate limiting must never produce status='complete'."""
        adapter = _make_adapter()
        mock_resp = _mock_response({}, status_code=429)

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            _, status = adapter.check_reputation(
                target_reference="example.com",
                url="https://example.com/",
            )

        assert status.status != "complete"


# ---------------------------------------------------------------------------
# 6. Authentication failure
# ---------------------------------------------------------------------------

class TestAuthFailure:
    def test_http_403_returns_error_http_403(self):
        """HTTP 403 (auth failure) must map to status='error', reason='http_403'."""
        adapter = _make_adapter(api_key="bad-key")
        mock_resp = _mock_response({"error": "forbidden"}, status_code=403)

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="example.com",
                url="https://example.com/page",
            )

        assert evidence == []
        assert status.status == "error"
        assert status.reason_code == "http_403"

    def test_auth_failure_never_returns_complete(self):
        """An authentication failure must never produce status='complete'."""
        adapter = _make_adapter(api_key="bad-key")
        mock_resp = _mock_response({}, status_code=403)

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            _, status = adapter.check_reputation(
                target_reference="example.com",
                url="https://example.com/",
            )

        assert status.status != "complete"


# ---------------------------------------------------------------------------
# 7. Malformed or unexpected provider responses
# ---------------------------------------------------------------------------

class TestMalformedResponses:
    def test_non_json_body_returns_error_invalid_response(self):
        """A response body that cannot be parsed as JSON maps to error/invalid_response."""
        adapter = _make_adapter()
        mock_resp = _mock_response("not valid json at all <<<", status_code=200)

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="example.com",
                url="https://example.com/page",
            )

        assert evidence == []
        assert status.status == "error"
        assert status.reason_code == "invalid_response"

    def test_matches_field_is_not_list_returns_error(self):
        """If 'matches' is not a list (e.g. a string), return error/invalid_response."""
        adapter = _make_adapter()
        mock_resp = _mock_response({"matches": "unexpected_string"})

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="example.com",
                url="https://example.com/",
            )

        assert evidence == []
        assert status.status == "error"
        assert status.reason_code == "invalid_response"

    def test_root_json_is_not_object_returns_error(self):
        """If the response root is a JSON array instead of object, return error."""
        adapter = _make_adapter()
        mock_resp = httpx.Response(
            status_code=200,
            content=b"[1, 2, 3]",
            headers={"Content-Type": "application/json"},
        )

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="example.com",
                url="https://example.com/",
            )

        assert evidence == []
        assert status.status == "error"
        assert status.reason_code == "invalid_response"

    def test_unknown_threat_type_still_produces_evidence(self):
        """An unrecognized threat type should still produce an evidence item (safe default)."""
        adapter = _make_adapter()
        mock_resp = _mock_response({
            "matches": [{"threatType": "FUTURE_UNKNOWN_TYPE", "platformType": "ANY_PLATFORM"}]
        })

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="example.com",
                url="https://example.com/",
            )

        assert status.status == "complete"
        assert len(evidence) == 1
        # Unrecognized threat type defaults to high severity (conservative)
        assert evidence[0].severity == "high"

    def test_oversized_response_returns_error(self):
        """A response body exceeding the size limit must return error/response_too_large."""
        from backend.app.providers.safe_browsing import _MAX_RESPONSE_BYTES
        adapter = _make_adapter()

        oversized_content = b"x" * (_MAX_RESPONSE_BYTES + 1)
        mock_resp = httpx.Response(
            status_code=200,
            content=oversized_content,
            headers={"Content-Type": "application/json"},
        )

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="example.com",
                url="https://example.com/",
            )

        assert evidence == []
        assert status.status == "error"
        assert status.reason_code == "response_too_large"

    def test_content_length_header_too_large_returns_error(self):
        """Content-Length header exceeding limit must return error/response_too_large."""
        from backend.app.providers.safe_browsing import _MAX_RESPONSE_BYTES
        adapter = _make_adapter()
        mock_resp = httpx.Response(
            status_code=200,
            content=b"{}",
            headers={
                "Content-Length": str(_MAX_RESPONSE_BYTES + 5000),
                "Content-Type": "application/json",
            },
        )

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="example.com",
                url="https://example.com/",
            )

        assert evidence == []
        assert status.status == "error"
        assert status.reason_code == "response_too_large"

    def test_malformed_responses_never_return_complete(self):
        """All malformed response types must yield non-'complete' status."""
        adapter = _make_adapter()
        mock_resp = _mock_response("invalid json <<<", status_code=200)

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.return_value = mock_resp
            mock_client_cls.return_value = mock_client

            _, status = adapter.check_reputation(
                target_reference="example.com",
                url="https://example.com/",
            )

        assert status.status != "complete"


# ---------------------------------------------------------------------------
# 8. Scheme validation
# ---------------------------------------------------------------------------

class TestSchemeValidation:
    def test_non_http_scheme_returns_unavailable_unsupported_scheme(self):
        """Non-http(s) schemes are rejected without network call."""
        adapter = _make_adapter()
        evidence, status = adapter.check_reputation(
            target_reference="example.com",
            url="ftp://example.com/file",
        )
        assert evidence == []
        assert status.status == "unavailable"
        assert status.reason_code == "unsupported_scheme"

    def test_javascript_scheme_rejected(self):
        adapter = _make_adapter()
        evidence, status = adapter.check_reputation(
            target_reference="example.com",
            url="javascript:alert(1)",
        )
        assert evidence == []
        assert status.status == "unavailable"
        assert status.reason_code == "unsupported_scheme"

    def test_data_scheme_rejected(self):
        adapter = _make_adapter()
        evidence, status = adapter.check_reputation(
            target_reference="example.com",
            url="data:text/html,<script>alert(1)</script>",
        )
        assert evidence == []
        assert status.status == "unavailable"
        assert status.reason_code == "unsupported_scheme"


# ---------------------------------------------------------------------------
# 9. Fragment sanitization (Privacy gate requirement)
# ---------------------------------------------------------------------------

class TestFragmentSanitization:
    def test_url_fragment_and_sensitive_query_params_stripped_before_submission(self):
        """URL fragments (#token) and sensitive query parameters (code, auth tokens)
        must be stripped before building the payload, while non-sensitive query parameters
        are preserved.
        """
        adapter = _make_adapter()
        mock_resp = _mock_response({})

        captured_requests = []
        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)

            def mock_post(url, json=None, **kwargs):
                captured_requests.append({"url": url, "json": json})
                return mock_resp

            mock_client.post.side_effect = mock_post
            mock_client_cls.return_value = mock_client

            evidence, status = adapter.check_reputation(
                target_reference="example.com",
                url="https://example.com/oauth/callback?category=security&code=123#access_token=secret_jwt_token",
            )

        assert status.status == "complete"
        assert len(captured_requests) == 1
        threat_entries = captured_requests[0]["json"]["threatInfo"]["threatEntries"]
        submitted_url = threat_entries[0]["url"]
        assert submitted_url == "https://example.com/oauth/callback?category=security"
        assert "code=123" not in submitted_url
        assert "#access_token=secret_jwt_token" not in submitted_url
        assert "secret_jwt_token" not in submitted_url


# ---------------------------------------------------------------------------
# 10. Secret redaction in logs and errors
# ---------------------------------------------------------------------------

class TestSecretRedactionInLogs:
    def test_unexpected_exception_redacts_api_key_from_logs(self, caplog):
        """Exceptions must log only type(exc).__name__, redacting API keys embedded in URLs."""
        adapter = _make_adapter(api_key="SUPER_CONFIDENTIAL_KEY_12345")

        with patch("httpx.Client") as mock_client_cls:
            mock_client = MagicMock()
            mock_client.__enter__ = MagicMock(return_value=mock_client)
            mock_client.__exit__ = MagicMock(return_value=False)
            mock_client.post.side_effect = RuntimeError(
                "Connection failed for https://safebrowsing.googleapis.com/v4/threatMatches:find?key=SUPER_CONFIDENTIAL_KEY_12345"
            )
            mock_client_cls.return_value = mock_client

            with caplog.at_level("WARNING"):
                evidence, status = adapter.check_reputation(
                    target_reference="example.com",
                    url="https://example.com/login",
                )

        assert evidence == []
        assert status.status == "error"
        assert status.reason_code == "provider_exception"
        assert "SUPER_CONFIDENTIAL_KEY_12345" not in caplog.text
        assert "RuntimeError" in caplog.text