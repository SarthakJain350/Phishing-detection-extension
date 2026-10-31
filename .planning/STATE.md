# Project State — Phishing Attack Detector

**Last Updated:** 2026-11-01
**Current Milestone:** Milestone 1 — Project Skeleton & Minimal End-to-End Vertical Slice (Days 1–3)
**Current Phase:** Phase 1 (COMPLETE: Tasks 1.1, 1.2, 1.3, 1.4 COMPLETE)
**Overall Progress:** Phase 1 Complete (Backend vertical slice + React Chrome Extension Popup MVP verified)

---

## Current Status Summary

- **Repository Inspection:** Completed. Analyzed all source-of-truth documents. Confirmed zero naming or directory conflicts.
- **Task 1.1 (Skeleton & Secret Guardrail):** COMPLETE.
  - Created root [.gitignore](file:///c:/Phishing%20Attack%20Detector/.gitignore).
  - Created placeholder-only [.env.example](file:///c:/Phishing%20Attack%20Detector/.env.example) with explicit CORS origin guidance.
  - Implemented [scripts/check_secrets.py](file:///c:/Phishing%20Attack%20Detector/scripts/check_secrets.py) (detects Google API keys, private keys, DB credentials, and staged `.env` files) with documented limitations.
  - Tested with [scripts/test_check_secrets.py](file:///c:/Phishing%20Attack%20Detector/scripts/test_check_secrets.py) (7/7 tests passing; repository scan clean).
- **Task 1.2 (Backend Infrastructure & Offline Domain Extraction):** COMPLETE.
  - Created backend dependencies in [requirements.txt](file:///c:/Phishing%20Attack%20Detector/backend/requirements.txt) and [requirements-dev.txt](file:///c:/Phishing%20Attack%20Detector/backend/requirements-dev.txt).
  - Implemented offline-safe domain normalization in [backend/app/core/domain.py](file:///c:/Phishing%20Attack%20Detector/backend/app/core/domain.py) using bundled Public Suffix List snapshot with zero runtime network fetching.
  - Implemented SQLAlchemy 2.0 scan models in [backend/app/db/models.py](file:///c:/Phishing%20Attack%20Detector/backend/app/db/models.py) with UUID identifiers, JSONB evidence/tool statuses, UTC timestamps, and check constraints (`0 <= risk_score <= 100`, `target_type`, `analysis_status`).
  - Created Alembic configuration and initial migration [001_initial_scans.py](file:///c:/Phishing%20Attack%20Detector/backend/alembic/versions/001_initial_scans.py).
  - Created [docker-compose.yml](file:///c:/Phishing%20Attack%20Detector/docker-compose.yml) for PostgreSQL 16 with persistent volume and health check.
  - Tested with pytest: 18 unit tests passed locally; 2 PostgreSQL live integration tests cleanly skipped pending Docker startup.
- **Task 1.3 (FastAPI API & Request Validation):** COMPLETE.
  - [backend/app/main.py](file:///c:/Phishing%20Attack%20Detector/backend/app/main.py): FastAPI app with standardized 400/404/500 error handlers and CORS middleware (no wildcard; explicit origins only).
  - [backend/app/api/v1/health.py](file:///c:/Phishing%20Attack%20Detector/backend/app/api/v1/health.py): `GET /api/v1/health` (liveness) and `GET /api/v1/health/ready` (DB readiness probe → 503 on failure).
  - [backend/app/api/v1/scans.py](file:///c:/Phishing%20Attack%20Detector/backend/app/api/v1/scans.py): `POST /api/v1/scans/website`, `POST /api/v1/scans/email`, `GET /api/v1/scans`, `GET /api/v1/scans/{scan_id}`.
  - [backend/app/schemas/scan.py](file:///c:/Phishing%20Attack%20Detector/backend/app/schemas/scan.py): Pydantic v2 request/response schemas with strict field validation (scheme, length, source enum, link cap).
  - [backend/app/detection/orchestrator.py](file:///c:/Phishing%20Attack%20Detector/backend/app/detection/orchestrator.py): `BaseDetectionOrchestrator` ABC + `MockDetectionOrchestrator` returning all 4 deterministic outcomes.
  - [backend/app/db/repository.py](file:///c:/Phishing%20Attack%20Detector/backend/app/db/repository.py): `ScanRepository.create_scan()`, `get_scan_by_id()`, `list_scans()` with privacy guarantee (hostname-only storage).
  - [backend/tests/test_api_v1.py](file:///c:/Phishing%20Attack%20Detector/backend/tests/test_api_v1.py): **22/22 tests passed** (health, 4 mock outcomes, validation rejections, email scan, pagination, UUID lookup, privacy boundary, CORS, safe 500).
  - Full regression: **40/40 offline tests passed** (Tasks 1.1 + 1.2 + 1.3 combined; PostgreSQL live tests cleanly excluded).
- **Task 1.4 (React Chrome Extension Popup MVP):** COMPLETE.
  - [extension/package.json](file:///c:/Phishing%20Attack%20Detector/extension/package.json): React 18, TypeScript 5.6, Vite 6, `@types/chrome`.
  - [extension/public/manifest.json](file:///c:/Phishing%20Attack%20Detector/extension/public/manifest.json): Manifest V3 with minimal permissions (`activeTab`, `scripting`) and host permissions scoped strictly to `http://127.0.0.1:8000/*` and `http://localhost:8000/*`.
  - [extension/src/popup/styles.css](file:///c:/Phishing%20Attack%20Detector/extension/src/popup/styles.css): Full Quiet Security design tokens (`canvas`, `surface`, `teal`, `ink`, `border`, `amber`, `red`, `slate`) with system dark-mode tokens, keyboard focus rings, restrained 3px semantic status bar on predominantly white `#FFFFFF` surface cards, clean LTR domain truncation, and tabular-figure typography.
  - [extension/src/popup/Popup.tsx](file:///c:/Phishing%20Attack%20Detector/extension/src/popup/Popup.tsx): Active domain display, "Scan current site" primary action, 5 UI states (idle, scanning, result, unavailable, connection/timeout error), progressive disclosure ("Why this result?"), non-probability disclaimer directly under score, non-fake quiet footer, and strict safety rules (unavailable/error is never shown as safe).
  - [extension/src/popup/api.ts](file:///c:/Phishing%20Attack%20Detector/extension/src/popup/api.ts): Typed client calling `POST /api/v1/scans/website` with exact `WebsiteScanRequest` shape and 5-second `AbortSignal.timeout`.
  - [extension/src/popup/icons.tsx](file:///c:/Phishing%20Attack%20Detector/extension/src/popup/icons.tsx): Clean inline SVGs (shield-link, danger, caution, check, unavailable, chevron) without external font or asset dependencies.
  - [extension/src/popup/types.ts](file:///c:/Phishing%20Attack%20Detector/extension/src/popup/types.ts): TypeScript interfaces matching backend Pydantic schemas exactly.
  - [README.md](file:///c:/Phishing%20Attack%20Detector/README.md): Comprehensive project documentation covering architecture, setup, endpoints, testing results, privacy safeguards, and limitations.
  - Verified with: `npm run type-check` (passed, zero errors) and `npm run build` (emitted production bundle in `extension/dist/` in 618ms).

---

## Active Decisions Log (Approved Corrections)

- **Decision 1 (CORS Origins):** Do NOT use wildcard `chrome-extension://*`. Backend CORS strictly validates against explicitly configured localhost origins (`http://localhost:3000`, `http://127.0.0.1:3000`) and the specific unpacked Chrome extension ID (`chrome-extension://<EXTENSION_ID>`).
- **Decision 2 (Offline-First tldextract PSL):** Domain normalization explicitly configures `tldextract.TLDExtract(suffix_list_urls=None, cache_dir=...)` to disable runtime HTTP fetching and rely on its bundled snapshot. Offline tests cover multi-level suffixes, IP addresses, trailing dots, and malformed URLs.
- **Decision 3 (Standardized Validation Errors):** All client-side invalid request payloads return HTTP 400 with standard `{ "error": { "code": "VALIDATION_ERROR", "message": "...", "request_id": "..." } }`.
- **Decision 4 (Data Privacy Boundary):** `scans.target_reference` stores normalized lowercase domain/hostname only. Full URLs, query parameters, auth tokens, page HTML, and email bodies are never persisted or logged.
- **Decision 5 (Secret Scanning Guardrail):** Pre-commit / pre-push scanner verifies no real credentials or `.env` files are committed.
- **Decision 6 (Latency Target):** Response time under 500ms is treated as a measured engineering target, not an unconditional acceptance blocker.
- **Decision 7 (Timeout Guardrail):** Extension request timeout is bounded to 5.0 seconds. A timeout is surfaced as an explicit, non-safe error panel with retry action.

---

## Next Steps

1. **User Review:** Inspect changed extension files and `README.md`.
2. **Phase 1 Checkpoint (Manual Chrome Verification):**
   - Start backend: `uvicorn backend.app.main:app --port 8000`
   - In Chrome `chrome://extensions/`: Load unpacked `extension/dist/`
   - Test popup on clean site (e.g. `wikipedia.org`), mock phishing pattern (e.g. `test-phish.com`), and with backend stopped.
3. **Phase 2 Technical Spikes & Detection Foundation:** Proceed once Phase 1 checkpoint is accepted.
