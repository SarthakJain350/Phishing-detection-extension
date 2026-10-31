# Requirements Specification — Phishing Attack Detector

**Document Version:** 1.0
**Status:** Approved for Implementation Planning
**Aligned With:** PRD, TRD, UI/UX Design Brief, App Flow, Backend Schema Spec

---

## 1. System Requirements Hierarchy

### 1.1 Core API & Data Contracts (`REQ-API`)

- **REQ-API-01: Health Endpoints**
  - The backend MUST expose `GET /api/v1/health` returning `{ "status": "ok" }`.
  - The backend MUST expose `GET /api/v1/health/ready` verifying active PostgreSQL connectivity and returning status for database and external provider configurations.
- **REQ-API-02: Website Scan Endpoint**
  - The backend MUST expose `POST /api/v1/scans/website`.
  - Request body MUST accept:
    - `url`: `HttpUrl` (required, max length 2048 chars, schemes `http` or `https` only).
    - `page_title`: `Optional[str]` (max length 256 chars).
    - `visible_text`: `Optional[str]` (max length 2000 chars, bounded text excerpt).
    - `source`: Enum (`manual_website`, `auto_website`).
- **REQ-API-03: Email Scan Endpoint**
  - The backend MUST expose `POST /api/v1/scans/email`.
  - Request body MUST accept:
    - `sender`: `Optional[str]` (max length 256 chars).
    - `subject`: `Optional[str]` (max length 256 chars).
    - `body_text`: `Optional[str]` (max length 3000 chars, bounded message text).
    - `links`: `List[HttpUrl]` (max 10 links, each max length 2048 chars).
    - `source`: Enum (`gmail`).
- **REQ-API-04: Scan History Endpoints**
  - The backend MUST expose `GET /api/v1/scans` accepting pagination query parameters (`limit: int = 20` max 100, `offset: int = 0`).
  - The backend MUST expose `GET /api/v1/scans/{scan_id}` returning a single scan by UUID.
  - The backend MUST expose `DELETE /api/v1/scans` to purge scan history on user request.
- **REQ-API-05: Unified Response Schema**
  - All scan endpoints MUST return:
    - `scan_id`: `UUID4`
    - `target_type`: `website` | `email`
    - `target_reference`: `str` (normalized domain/hostname only, e.g., `login.example.com`)
    - `classification`: `Optional[str]` (`phishing`, `suspicious`, `likely_legitimate`, or `null` if unavailable)
    - `risk_score`: `Optional[int]` (0–100, or `null` if unavailable)
    - `reasons`: `List[str]` (1–3 concise plain-language evidence statements)
    - `evidence`: `List[EvidenceItem]` (each containing `type: str`, `source: str`, `severity: low|medium|high`, `explanation: str`)
    - `tool_statuses`: `ToolStatuses` (`heuristics`, `reputation`, `llm` with `status: complete|partial|unavailable|timeout|error` and optional `reason_code`)
    - `analysis_status`: `complete` | `partial` | `unavailable`
    - `source`: `str`
    - `created_at`: `datetime` (UTC ISO 8601)
- **REQ-API-06: Error Responses**
  - All error responses MUST follow `{ "error": { "code": str, "message": str, "request_id": Optional[str] } }`.
  - Server MUST return 400 for validation errors, 413 for payload oversized, 502/503 for fatal dependency errors.

---

### 1.2 Detection Pipeline & Agent (`REQ-DET`)

- **REQ-DET-01: Orchestration Pipeline**
  - The detection orchestrator MUST execute: (1) Input normalization & validation, (2) Deterministic heuristics, (3) Reputation adapter lookup, (4) Gemini analysis adapter, (5) Deterministic evidence combination & scoring, (6) PostgreSQL persistence.
- **REQ-DET-02: Deterministic Heuristic Engine**
  - Heuristics MUST evaluate:
    - IP address used as hostname (e.g., `http://192.168.1.1/login`).
    - Suspicious TLD / Punycode / IDN homograph patterns.
    - Misleading subdomain structures (e.g., `paypal.com.security-check.xyz`).
    - Excessive URL length or suspicious special character counts.
    - Mismatch between visible link text and destination link (when available).
    - Urgent action / credential harvesting keywords in bounded text.
- **REQ-DET-03: Reputation Provider Adapter**
  - The system MUST implement an abstract `ReputationProvider` interface.
  - Implement a `MockReputationProvider` for tests and local dev without external keys.
  - Implement a `GoogleSafeBrowsingAdapter` supporting Google Safe Browsing Lookup API v4 when an API key is provided.
  - Provider timeouts MUST be bounded to 3.0 seconds and MUST gracefully fail to `tool_statuses.reputation.status = 'unavailable'` without failing the overall scan.
- **REQ-DET-04: Gemini LLM Adapter**
  - Gemini API key MUST be loaded server-side from environment (`GEMINI_API_KEY`).
  - Model calls MUST use structured JSON output mode with a strict Pydantic response schema (`classification`, `risk_score: int 0-100`, `reasons: List[str]`, `confidence_label: low|medium|high`).
  - Prompt MUST explicitly declare user page/email text as untrusted data to defend against prompt injection attacks.
  - Calls MUST use bounded timeout (max 5.0 seconds) and bounded retry (maximum 1 retry on 429/503).
  - On failure, quota exhaustion, or malformed JSON, Gemini status MUST be marked `unavailable` or `error`.
- **REQ-DET-05: Deterministic Decision Combiner**
  - The final classification and risk score MUST be computed deterministically:
    - High-risk / `phishing` (score >= 75): Confirmed reputation hit OR strong heuristic indicators (e.g., misleading subdomain + urgency) corroborated by Gemini.
    - Cautionary / `suspicious` (score 40–74): Moderate heuristic findings, or conflicting signals between tools.
    - Low-risk / `likely_legitimate` (score 0–39): Clean heuristics, clean reputation (if available), and low Gemini risk.
    - `unavailable`: If heuristics cannot run or if all primary tools fail to produce a usable result. `risk_score` MUST be `None` and `classification` MUST be `None`.
- **REQ-DET-06: Failure Handling Guardrails**
  - A failed reputation lookup or failed Gemini API call MUST NEVER cause a target to be marked `likely_legitimate`.
  - When Gemini fails but heuristics succeed, `analysis_status` MUST be `partial` with a clearly labeled slate UI state.

---

### 1.3 Database & Privacy (`REQ-DB`)

- **REQ-DB-01: PostgreSQL Schema (`scans` Table)**
  - Primary key: `id UUID PRIMARY KEY`.
  - Columns: `target_type TEXT`, `target_reference TEXT NOT NULL`, `classification TEXT NULL`, `risk_score SMALLINT NULL`, `evidence JSONB NOT NULL`, `tool_statuses JSONB NOT NULL`, `analysis_status TEXT NOT NULL`, `source TEXT NOT NULL`, `created_at TIMESTAMPTZ DEFAULT NOW()`.
  - Constraints: Check constraint on `risk_score BETWEEN 0 AND 100`, `target_type IN ('website', 'email')`, `analysis_status IN ('complete', 'partial', 'unavailable')`.
- **REQ-DB-02: Domain Normalization & Privacy**
  - `target_reference` MUST contain lowercase domain/hostname only (e.g., `example.com`).
  - The database MUST NOT store full URLs, URL queries/tokens, full webpage HTML, full email bodies, or sender personal identifiers.
- **REQ-DB-03: Indexing**
  - Indexes MUST be created on: `created_at DESC` (for pagination), `(target_reference, created_at DESC)`, and `(classification, created_at DESC)`.
- **REQ-DB-04: Retention & Cleanup**
  - Scans older than 30 days MUST be deleted.
  - A scheduled background task or maintenance command MUST execute the 30-day retention query without impacting real-time scan latency.

---

### 1.4 Browser Extension & UI/UX (`REQ-EXT` & `REQ-UI`)

- **REQ-EXT-01: Manifest V3 Architecture**
  - Permissions strictly minimized: `activeTab`, `storage`, `alarms`, `scripting`. Host permissions limited to local backend (`http://localhost:8000/*` or `http://127.0.0.1:8000/*`).
  - Background Service Worker coordinates messages and survives MV3 worker suspension without loss of active scan requests.
- **REQ-UI-01: Quiet Security Design Tokens**
  - UI MUST implement the token palette:
    - Light: `canvas: #F7F5F0`, `surface: #FFFFFF`, `ink: #17212B`, `muted: #5F6B75`, `border: #D8DEE3`, `teal: #0F766E`, `teal-soft: #E5F3F0`, `amber: #9A5B00`, `amber-soft: #FFF1D6`, `red: #B42318`, `red-soft: #FDECEA`, `slate-soft: #EDF1F4`, `focus: #2563EB`.
    - Dark mode tokens supported via CSS variables or themed context.
- **REQ-UI-02: Popup User Interface**
  - Popup MUST show: Product header (Shield icon + "Phishing Attack Detector"), active domain, primary action ("Scan current site"), loading state, and result presentation.
  - Progressive disclosure: Collapsed view shows classification, score (e.g., `82 / 100` "Risk score"), and up to 2 reasons. Expandable "Why this result?" shows full evidence and tool status.
- **REQ-UI-03: High-Risk Warning Interstitial**
  - Detected high-risk navigations or links MUST present a prominent interstitial:
    - Primary action: "Go back to safety" (teal/neutral safe button).
    - Secondary action: "Continue anyway" (quieter, explicit manual override).
- **REQ-EXT-02: Gmail Inline Integration**
  - Content script detects active message thread; user triggers "Scan this email".
  - Extracts sender domain, subject, bounded body text excerpt, and link URLs.
  - Displays inline result panel adjacent to message or falls back to popup display.

---

### 1.5 Testing & Evaluation (`REQ-TEST` & `REQ-EVAL`)

- **REQ-TEST-01: Automated Test Suite**
  - Backend pytest coverage covering:
    - Unit tests: URL parsing, domain normalization, heuristic rules, decision combiner logic, Pydantic schemas.
    - Integration tests: FastAPI endpoints with mocked DB and mocked providers, database repository CRUD, pagination, 30-day cleanup.
    - Failure mode tests: Gemini quota exceeded (429), timeout, invalid JSON, reputation timeout, DB disconnection.
    - Concurrency test: Multiple simultaneous scan requests under bounded timeouts.
- **REQ-EVAL-01: Dataset Evaluation Pipeline**
  - Public dataset (e.g., PhishTank / Mendeley Phishing URLs) + legitimate baseline URLs (e.g., Tranco / Alexa top domains).
  - Comparative evaluation script measuring:
    1. Heuristics-only baseline
    2. Heuristics + Reputation
    3. Full pipeline (Heuristics + Reputation + Gemini)
  - Output report metrics: Precision, Recall, F1 Score, False-Positive Rate (FPR), Confusion Matrix, and Latency distribution (p50, p95).

---

## 2. Explicit Non-Goals / Out of Scope

1. **No User Accounts:** No user authentication, passwords, or multi-tenant authorization in the prototype.
2. **No Full Mailbox Crawling:** Scans only the single open/selected email on explicit user action.
3. **No Synchronous Browser Navigation Lock:** Manifest V3 does not support arbitrary synchronous interception of dynamic requests; warning page + link click interception is the verified model.
4. **No Custom Foundation Model Training:** Utilizes Gemini API via prompt engineering and structured schema outputs.
5. **No Guarantee of Infallibility:** Results are advisory risk assessments with explicit failure semantics.
