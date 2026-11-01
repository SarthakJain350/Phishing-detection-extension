# Phase 2: Technical Feasibility Spikes & Detection Foundation — Validation Strategy

**Gathered:** 2026-11-01
**Status:** Complete

## Validation Architecture

### 1. Heuristics Engine Automated Testing (`backend/tests/test_heuristics.py`)
- **Unit Test Coverage:**
  - `test_ip_hostname`: Validates standard IPv4 (`http://192.168.1.1/login`), IPv6 literals, and benign domains (`https://google.com`).
  - `test_punycode_and_homoglyphs`: Validates `xn--` Cyrillic spoofing (`http://xn--pypal-4ve.com`) vs legitimate ASCII domains.
  - `test_misleading_subdomains`: Validates `https://paypal.com.account-update.xyz` (flagged) vs `https://checkout.paypal.com` (clean).
  - `test_url_structure_anomalies`: Validates length > 100, `@` in authority/path, excessive hyphens (`pay-pal-security-update-now.com`).
  - `test_urgency_and_credential_language`: Validates urgent threats ("your account will be suspended within 24 hours") vs normal newsletter text.
  - `test_full_heuristic_aggregation`: Runs `DeterministicHeuristicsEngine.evaluate()` and verifies returning structured `list[EvidenceItem]`.

### 2. Gemini Adapter Automated Testing (`backend/tests/test_gemini_adapter.py`)
- **Unit / Mock Test Coverage:**
  - `test_gemini_adapter_success`: Mocks valid structured JSON output and verifies Pydantic parsing into `GeminiAnalysisResult`.
  - `test_gemini_adapter_invalid_json`: Mocks truncated or malformed JSON; verifies graceful handling returning `status="unavailable"`, `reason_code="invalid_response"`.
  - `test_gemini_adapter_timeout`: Simulates 5.0s timeout; verifies returning `status="timeout"` without uncaught exceptions.
  - `test_gemini_adapter_rate_limit_retry`: Simulates single 429 response followed by success; verifies retry behavior.
  - `test_gemini_adapter_missing_key`: When `GEMINI_API_KEY` is None/empty, verifies immediate degraded return (`status="unavailable"`, `reason_code="no_api_key"`).
  - `test_prompt_injection_defense`: Verifies untrusted content formatting with `<untrusted_content>` wrapping.

### 3. Regression Safeguards
- All 40 existing backend tests in `backend/tests/test_api_v1.py`, `test_domain_offline.py`, `test_models.py`, `test_migration_schema.py` must continue passing 100%.
- Secret scanner `scripts/check_secrets.py` must continue passing with zero detected credentials.
- Frontend builds `npm run type-check` and `npm run build` must remain clean.
