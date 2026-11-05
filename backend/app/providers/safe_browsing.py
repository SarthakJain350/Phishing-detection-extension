"""Google Safe Browsing Lookup API v4 — server-side reputation adapter.

SECURITY GUARDRAILS — READ BEFORE MODIFYING:

1. API KEY ISOLATION
   SAFE_BROWSING_API_KEY is loaded exclusively from server-side environment /
   .env. It is NEVER included in scan responses, logs, error messages, or any
   client-facing output. The key is appended only to the outbound HTTPS request
   URL (as required by the Safe Browsing Lookup API).

2. DATA MINIMISATION
   Only the website URL is submitted to Google Safe Browsing. No page contents,
   visible text, email bodies, cookies, credentials, or user identifiers are
   sent. The full URL is forwarded to Google (required by the Lookup API) but is
   NEVER written to local logs or the database. Only the normalized hostname
   (target_reference) is persisted.

3. FAIL-SAFE DEGRADATION
   Any failure path (missing key, timeout, HTTP error, invalid JSON, schema
   validation error, unexpected exception) returns a ToolStatusDetail with a
   non-"complete" status. The adapter NEVER returns a "likely_legitimate"
   reputation signal as a consequence of a failure — it returns
   ([], error_status) and lets the orchestrator make the safe call.

4. BOUNDED TIMEOUT (10.0 s total, no automatic retry)
   The Safe Browsing Lookup API is low-latency (100–300 ms typical). A 10-second
   wall-clock budget is enforced. No automatic retry is performed — rate-limit
   responses (429) are returned immediately as "unavailable/rate_limited" to
   preserve quota and avoid thundering herd.

5. NO ADDITIONAL URL FETCHING
   The adapter forwards only the URL supplied by the caller. It never fetches
   the target URL or any other external resource.

6. RESPONSE SIZE LIMIT
   Responses are read with a capped size limit to guard against unexpectedly
   large payloads from the provider.

7. EMAIL EXCLUSION (Phase 1)
   This adapter is intentionally not connected to the email scan path. Email
   reputation integration is deferred to a future phase.

Privacy gate approval: .planning/privacy-gate-safe-browsing.md
"""

from __future__ import annotations

import logging
import time
from typing import Any
import urllib.parse

import httpx

from backend.app.core.config import settings
from backend.app.schemas.scan import EvidenceItem, ToolStatusDetail

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Safe Browsing API constants
# ---------------------------------------------------------------------------

_SB_LOOKUP_URL = (
    "https://safebrowsing.googleapis.com/v4/threatMatches:find"
)

# Total wall-clock budget for one check_reputation call (no retry)
_TOTAL_TIMEOUT_SECONDS = 10.0

# Maximum bytes accepted from the provider to guard against giant payloads
_MAX_RESPONSE_BYTES = 64 * 1024  # 64 KB

# Threat types relevant to phishing detection
_THREAT_TYPES = [
    "SOCIAL_ENGINEERING",
    "MALWARE",
    "UNWANTED_SOFTWARE",
]

# Severity mapping: threat type → evidence severity
_THREAT_SEVERITY: dict[str, str] = {
    "SOCIAL_ENGINEERING": "high",
    "MALWARE": "high",
    "UNWANTED_SOFTWARE": "medium",
    "POTENTIALLY_HARMFUL_APPLICATION": "medium",
}

# Human-readable threat type labels
_THREAT_LABELS: dict[str, str] = {
    "SOCIAL_ENGINEERING": "social engineering / phishing",
    "MALWARE": "malware distribution",
    "UNWANTED_SOFTWARE": "unwanted software",
    "POTENTIALLY_HARMFUL_APPLICATION": "potentially harmful application",
}

# Client metadata required by the Safe Browsing Lookup API
_CLIENT_ID = "phishing-attack-detector"
_CLIENT_VERSION = "1.0.0"

# Sensitive query parameter keys that must never be forwarded to external providers
_SENSITIVE_QUERY_PARAMS: frozenset[str] = frozenset({
    "token", "access_token", "id_token", "auth", "code", "secret", "session",
    "session_id", "sessionid", "sid", "key", "api_key", "apikey", "password",
    "pass", "pwd", "email", "user", "username", "jwt", "sig", "signature",
    "ticket", "reset_token", "oauth_token", "credential",
})


def _sanitize_url_for_lookup(url: str) -> str:
    """Sanitize URL before external threat lookup:
    1. Strip URL fragments (#fragment).
    2. Remove sensitive query parameters (auth tokens, session IDs, credentials)
       so client secrets are never forwarded to Google Safe Browsing.
    """
    clean_url, _ = urllib.parse.urldefrag(url)
    parsed = urllib.parse.urlsplit(clean_url)
    if not parsed.query:
        return clean_url

    query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
    filtered_pairs = [
        (k, v) for k, v in query_pairs
        if k.lower() not in _SENSITIVE_QUERY_PARAMS
    ]
    new_query = urllib.parse.urlencode(filtered_pairs)
    return urllib.parse.urlunsplit((
        parsed.scheme,
        parsed.netloc,
        parsed.path,
        new_query,
        "",
    ))


# ---------------------------------------------------------------------------
# Internal response model
# ---------------------------------------------------------------------------

def _map_threat_to_evidence(match: dict[str, Any], url: str) -> EvidenceItem:
    """Convert a single Safe Browsing threat match into an EvidenceItem."""
    threat_type = match.get("threatType", "UNKNOWN_THREAT")
    label = _THREAT_LABELS.get(threat_type, threat_type.replace("_", " ").lower())
    severity = _THREAT_SEVERITY.get(threat_type, "high")

    return EvidenceItem(
        type="reputation_threat",
        source="reputation",
        severity=severity,
        explanation=(
            f"Google Safe Browsing flagged this URL as {label}. "
            "This is a strong signal of malicious intent."
        ),
    )


# ---------------------------------------------------------------------------
# SafeBrowsingAdapter
# ---------------------------------------------------------------------------

class SafeBrowsingAdapter:
    """Server-side adapter for the Google Safe Browsing Lookup API v4.

    Usage:
        adapter = SafeBrowsingAdapter()
        evidence, status = adapter.check_reputation(
            target_reference="paypal.com.evil-phish.xyz",
            url="https://paypal.com.evil-phish.xyz/login?next=steal",
        )
        if status.status == "complete" and evidence:
            # Reputation provider confirmed a threat — evidence contains details
        elif status.status == "complete" and not evidence:
            # Provider completed lookup and found no known threat
        else:
            # Provider unavailable/error — NEVER treat as clean

    Returns:
        (evidence_list, ToolStatusDetail) where:
        - evidence_list is [] on clean lookup or provider failure (never None)
        - ToolStatusDetail.status is "complete" on successful API response
          (regardless of whether a threat was found)
        - ToolStatusDetail.status is non-"complete" on any failure
    """

    def __init__(self) -> None:
        # Loaded once at construction; never mutated or logged after this point.
        self._api_key: str | None = settings.SAFE_BROWSING_API_KEY or None

    # ------------------------------------------------------------------
    # Public interface — matches the duck-typed orchestrator contract
    # ------------------------------------------------------------------

    def check_reputation(
        self,
        *,
        target_reference: str,
        url: str,
    ) -> tuple[list[EvidenceItem], ToolStatusDetail]:
        """Check a URL against the Google Safe Browsing threat database.

        Args:
            target_reference: Normalized hostname used for logging only.
                              This value is safe to include in structured logs.
            url:              Full website URL to check (http/https only).
                              NEVER log this value — it may contain tokens.

        Returns:
            (evidence, status) tuple. evidence is always a list (never None).
            An empty list means no threat found or lookup unavailable.
            The status always conveys whether the lookup completed successfully.

        This method is guaranteed to never raise an unhandled exception.
        """
        # Gate 1: API key check — fast path, no network call
        if not self._api_key:
            logger.debug(
                "Safe Browsing API key not configured; reputation check disabled."
            )
            return [], ToolStatusDetail(
                status="unavailable",
                reason_code="no_api_key",
            )

        # Gate 2: Scheme validation — only http/https is safe to submit
        url_lower = url.lower()
        if not (url_lower.startswith("http://") or url_lower.startswith("https://")):
            logger.debug(
                "Safe Browsing check skipped for non-http URL scheme (target=%s).",
                target_reference,
            )
            return [], ToolStatusDetail(
                status="unavailable",
                reason_code="unsupported_scheme",
            )

        # Sanitize URL: strip fragments (#fragment) and sensitive query parameters
        # (tokens, session IDs, passwords, auth codes) prior to external transmission.
        sanitized_url = _sanitize_url_for_lookup(url)

        return self._execute_lookup(target_reference=target_reference, url=sanitized_url)

    # ------------------------------------------------------------------
    # Internal HTTP layer
    # ------------------------------------------------------------------

    def _execute_lookup(
        self,
        *,
        target_reference: str,
        url: str,
    ) -> tuple[list[EvidenceItem], ToolStatusDetail]:
        """Execute a single Safe Browsing Lookup API call within the timeout budget."""
        deadline = time.monotonic() + _TOTAL_TIMEOUT_SECONDS
        time_remaining = deadline - time.monotonic()

        if time_remaining <= 0:
            return [], ToolStatusDetail(
                status="timeout",
                reason_code="deadline_exceeded",
            )

        timeout = httpx.Timeout(
            connect=min(3.0, time_remaining),
            read=time_remaining,
            write=time_remaining,
            pool=time_remaining,
        )

        request_body = {
            "client": {
                "clientId": _CLIENT_ID,
                "clientVersion": _CLIENT_VERSION,
            },
            "threatInfo": {
                "threatTypes": _THREAT_TYPES,
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                # SECURITY: url may contain query tokens — never log it
                "threatEntries": [{"url": url}],
            },
        }

        # Append key to URL as required by the Lookup API — never include in logs
        lookup_url = f"{_SB_LOOKUP_URL}?key={self._api_key}"

        request_started = time.monotonic()
        try:
            with httpx.Client(timeout=timeout) as client:
                response = client.post(
                    lookup_url,
                    json=request_body,
                    headers={"Content-Type": "application/json"},
                )
            logger.debug(
                "Safe Browsing HTTP request completed in %.2fs with status %d (target=%s).",
                time.monotonic() - request_started,
                response.status_code,
                target_reference,
            )
        except httpx.TimeoutException as exc:
            logger.warning(
                "Safe Browsing API timed out after %.2fs (target=%s): %s",
                time.monotonic() - request_started,
                target_reference,
                type(exc).__name__,
            )
            return [], ToolStatusDetail(
                status="timeout",
                reason_code="request_timeout",
            )
        except httpx.HTTPError as exc:
            logger.warning(
                "Safe Browsing HTTP transport error after %.2fs (target=%s): %s",
                time.monotonic() - request_started,
                target_reference,
                type(exc).__name__,
            )
            return [], ToolStatusDetail(
                status="unavailable",
                reason_code="http_transport_error",
            )
        except Exception as exc:
            # SECURITY: Catch unexpected adapter/client exceptions at this boundary.
            # Log ONLY type(exc).__name__ to prevent leaking lookup_url (which contains
            # the API key in its query string) or any request body tokens into logs.
            logger.warning(
                "Safe Browsing unexpected exception after %.2fs (target=%s): %s",
                time.monotonic() - request_started,
                target_reference,
                type(exc).__name__,
            )
            return [], ToolStatusDetail(
                status="error",
                reason_code="provider_exception",
            )

        # Defensive check against Content-Length header exceeding limit
        content_length_str = response.headers.get("content-length")
        if content_length_str and content_length_str.isdigit():
            if int(content_length_str) > _MAX_RESPONSE_BYTES:
                logger.warning(
                    "Safe Browsing response Content-Length header too large (%s bytes) for target=%s.",
                    content_length_str,
                    target_reference,
                )
                return [], ToolStatusDetail(
                    status="error",
                    reason_code="response_too_large",
                )

        # Rate limiting — do not retry; preserve quota
        if response.status_code == 429:
            logger.warning(
                "Safe Browsing API rate limit reached (target=%s).", target_reference
            )
            return [], ToolStatusDetail(
                status="unavailable",
                reason_code="rate_limited",
            )

        # Authentication failure
        if response.status_code == 403:
            logger.warning(
                "Safe Browsing API authentication failure HTTP 403 (target=%s).",
                target_reference,
            )
            return [], ToolStatusDetail(
                status="error",
                reason_code="http_403",
            )

        # Other non-2xx errors
        if not response.is_success:
            logger.warning(
                "Safe Browsing API returned HTTP %d (target=%s).",
                response.status_code,
                target_reference,
            )
            return [], ToolStatusDetail(
                status="error",
                reason_code=f"http_{response.status_code}",
            )

        return self._parse_response(response, target_reference=target_reference)

    def _parse_response(
        self,
        response: httpx.Response,
        *,
        target_reference: str,
    ) -> tuple[list[EvidenceItem], ToolStatusDetail]:
        """Parse a successful HTTP 2xx Safe Browsing response.

        The Safe Browsing Lookup API returns either:
        - An empty JSON object {}  — no threats found (clean)
        - {"matches": [...]}       — one or more threat matches

        Returns (evidence_list, ToolStatusDetail(status="complete")) on success.
        """
        # Guard against unexpectedly large response bodies
        if len(response.content) > _MAX_RESPONSE_BYTES:
            logger.warning(
                "Safe Browsing response too large (%d bytes) for target=%s; ignoring.",
                len(response.content),
                target_reference,
            )
            return [], ToolStatusDetail(
                status="error",
                reason_code="response_too_large",
            )

        try:
            body: dict[str, Any] = response.json()
        except ValueError as exc:
            logger.debug(
                "Safe Browsing response body is not valid JSON (target=%s): %s",
                target_reference,
                exc,
            )
            return [], ToolStatusDetail(
                status="error",
                reason_code="invalid_response",
            )

        if not isinstance(body, dict):
            logger.debug(
                "Safe Browsing response is not a JSON object (target=%s).",
                target_reference,
            )
            return [], ToolStatusDetail(
                status="error",
                reason_code="invalid_response",
            )

        matches = body.get("matches")

        # Empty object {} or {"matches": []} → clean result
        if not matches:
            logger.debug(
                "Safe Browsing: no threats detected (target=%s).", target_reference
            )
            return [], ToolStatusDetail(status="complete")

        if not isinstance(matches, list):
            logger.debug(
                "Safe Browsing 'matches' field is not a list (target=%s).", target_reference
            )
            return [], ToolStatusDetail(
                status="error",
                reason_code="invalid_response",
            )

        # Build evidence items — one per unique threat type to avoid duplicates
        seen_types: set[str] = set()
        evidence: list[EvidenceItem] = []
        for match in matches:
            if not isinstance(match, dict):
                continue
            threat_type = match.get("threatType", "UNKNOWN_THREAT")
            if threat_type not in seen_types:
                seen_types.add(threat_type)
                evidence.append(_map_threat_to_evidence(match, url="<redacted>"))

        logger.debug(
            "Safe Browsing: %d threat type(s) detected (target=%s): %s",
            len(seen_types),
            target_reference,
            ", ".join(seen_types),
        )

        if not evidence:
            # Malformed matches list with no parseable entries
            return [], ToolStatusDetail(
                status="error",
                reason_code="invalid_response",
            )

        return evidence, ToolStatusDetail(status="complete")