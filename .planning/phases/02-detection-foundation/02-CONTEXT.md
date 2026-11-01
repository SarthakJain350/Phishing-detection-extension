# Phase 2: Technical Feasibility Spikes & Detection Foundation — Context

**Gathered:** 2026-11-01
**Status:** Ready for planning
**Source:** Specifications (`REQUIREMENTS.md`, `ROADMAP.md`, `Phishing_Detection_Implementation_Plan_Sarthak.md`, `Phishing_Detection_TRD_Antigravity.md`)

<domain>
## Phase Boundary

Phase 2 establishes the detection foundation and validates browser feasibility before end-to-end integration:
1. **Sarthak (Backend Detection Foundation):**
   - Deterministic URL and text heuristics engine (`backend/app/detection/heuristics.py`).
   - Server-side Gemini API provider adapter with strict Pydantic structured output (`backend/app/providers/gemini.py`).
   - Unit tests for heuristics and mock/error tests for Gemini adapter.
2. **Rohan (Browser Feasibility Spikes — Separately Scoped):**
   - Chrome MV3 navigation warning mechanism spike (`warning.html` interstitial).
   - Gmail open message DOM extraction spike on active tab.
3. **Out of Scope for Phase 2:**
   - Reputation provider adapters (Google Safe Browsing / VirusTotal) -> Phase 3.
   - Evidence combiner / final decision policy -> Phase 3.
   - Live extension wiring to real detection orchestrator -> Phase 4.
   - History deletion -> Phase 4.
</domain>

<decisions>
## Implementation Decisions

### Deterministic Heuristics Engine (Sarthak)
- **Module:** `backend/app/detection/heuristics.py`.
- **Interface:** Must return list of structured `EvidenceItem` objects (matching `backend/app/schemas/scan.py` schema: `type`, `source="heuristics"`, `severity="low"|"medium"|"high"`, `explanation`).
- **Detectors:**
  1. `detect_ip_hostname`: Flags IPv4/IPv6 address used directly as hostname (e.g. `http://192.168.1.1/login`).
  2. `detect_punycode_and_lookalike`: Flags `xn--` punycode and mixed-script or suspicious homoglyph patterns.
  3. `detect_misleading_subdomains`: Flags brands or security keywords embedded in subdomains (e.g. `paypal.com.account-update.xyz`).
  4. `detect_url_structure_anomalies`: Flags excessive URL length (>100 chars), high path/query entropy, multiple `@` symbols, excessive hyphens/dots.
  5. `detect_urgency_and_credential_keywords`: Evaluates bounded visible text or email subject/body for high-pressure credential harvesting phrases ("urgent", "verify account immediately", "suspend within 24 hours").
- **Offline Guarantee:** Zero external network calls. All checks operate strictly in-memory using python standard library (`ipaddress`, `urllib.parse`, `re`) and `tldextract`'s offline PSL cache.

### Gemini Provider Adapter (Sarthak)
- **Module:** `backend/app/providers/gemini.py`.
- **SDK / Client:** Uses `google-genai` or direct HTTPS requests with `httpx` to Gemini REST endpoint (`v1beta`).
- **Secret Handling:** Server-side `settings.GEMINI_API_KEY` only; never passed to client or logged.
- **Output Schema:** Enforces strict Pydantic model:
  ```python
  class GeminiDetectionOutput(BaseModel):
      classification: Literal["phishing", "suspicious", "likely_legitimate"]
      risk_score: int = Field(..., ge=0, le=100)
      reasons: list[str]
      confidence_label: Literal["low", "medium", "high"]
  ```
- **Prompt Injection Defense:** Input text (page visible text or email content) is encapsulated within strict XML tags (`<untrusted_content>`) with system instructions stating content is untrusted data and must never be interpreted as commands.
- **Timeouts & Retries:** Bounded 5.0s timeout; at most 1 retry on 429/503.
- **Degraded Status:** Returns `ToolStatusDetail(status="unavailable"|"timeout"|"error"|"complete")`. Never throws unhandled exceptions to callers. Provider failure never defaults to a legitimate/safe verdict.

### Browser Feasibility Spikes (Rohan - Separately Scoped)
- Spike 1: Chrome MV3 navigation interception investigation (`chrome.webNavigation.onBeforeNavigate` vs link click interception) and standalone `warning.html`.
- Spike 2: Gmail DOM thread extraction prototype.
- Kept isolated in separate spike directories/files so backend detection foundation can proceed without browser blocking.
</decisions>

<canonical_refs>
## Canonical References

- `Phishing_Detection_TRD_Antigravity.md` §7 — Detection agent requirements (heuristics, Gemini adapter).
- `Phishing_Detection_Implementation_Plan_Sarthak.md` §3 (Days 3 & 4) — Sarthak's deliverables for heuristics and Gemini.
- `.planning/REQUIREMENTS.md` §1.2 (`REQ-DET-02`, `REQ-DET-04`) — Requirements specification.
- `backend/app/schemas/scan.py` — Existing Pydantic schemas for `EvidenceItem` and `ToolStatusDetail`.
</canonical_refs>
