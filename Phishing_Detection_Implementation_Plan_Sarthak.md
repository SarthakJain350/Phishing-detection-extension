# Phishing Attack Detector — Implementation Plan for Sarthak

**Owner:** Sarthak  
**Project duration:** 15 days  
**Primary ownership:** React popup/UI, detection pipeline, Gemini adapter, heuristics, evidence combination, PostgreSQL repository, Docker/CI, and integration quality.

## 1. Goal

Deliver a working, testable detection pipeline that takes a website URL or email content from the extension/backend contract, runs available checks, returns a structured verdict with evidence and tool statuses, and persists minimized scan metadata in PostgreSQL.

The extension must not label a target as safe simply because a provider failed. A risk score is a **0–100 score**, not a calibrated probability. Results must distinguish `complete`, `partial`, and `unavailable` analysis.

## 2. What Sarthak owns

- React popup result presentation and reusable UI states.
- Detection orchestrator and deterministic heuristic checks.
- Gemini API adapter, bounded retries, response validation, and failure handling.
- Deterministic evidence combination and risk score calculation.
- PostgreSQL schema, repository, and persistence tests.
- Docker setup, environment configuration, CI/test workflow, and integration hardening.
- Coordinate with Rohan on API contracts and end-to-end behavior.

Rohan owns FastAPI route implementation, browser website/Gmail integration, and evaluation scripts. Sarthak should provide the detection and persistence modules behind the agreed interface rather than duplicating Rohan’s route or extension integration work.

## 3. Fifteen-day schedule

### Day 1 — Inspect repository and lock the contract
- Inspect existing files, package versions, working code, and current run commands before changing anything.
- Confirm request/response shapes with Rohan for website and email scans.
- Agree on shared types: `classification`, `risk_score`, `evidence`, `tool_statuses`, and `analysis_status`.
- Create a short list of environment variables; keep API keys server-side.
- Set up a branch and a small test scaffold.

**Deliverable:** repository map, agreed interface, setup instructions, and first passing baseline test.

### Day 2 — Build the database foundation
- Implement the PostgreSQL `scans` table and indexes from the agreed schema.
- Use UUID scan IDs, minimized domain-only target references, JSONB evidence/tool statuses, timestamps, source, and analysis status.
- Keep full webpage/email content out of stored records by default.
- Implement repository functions to create a scan and retrieve recent scans/by ID.
- Ensure unavailable analyses can be represented without pretending the target is legitimate; use nullable classification/risk score where required by the API contract.

**Deliverable:** migration/schema, repository skeleton, and database tests.

### Day 3 — Implement deterministic heuristics
- Add small, explainable checks for suspicious URL patterns, IP-address hosts, misleading subdomains, punycode, excessive URL length, and credential/urgency language when email text is available.
- Keep each check as a separate function returning structured evidence, not just a Boolean.
- Normalize URLs carefully and avoid treating any one weak signal as proof of phishing.
- Add positive, negative, and edge-case unit tests.

**Deliverable:** heuristic module with structured evidence and tests.

### Day 4 — Implement Gemini adapter
- Create a single provider adapter with one configured API key.
- Send only bounded, necessary input; avoid sending unrelated page or email data.
- Request strict structured output and validate the response before use.
- Use bounded retries/timeouts; do not create quota bypasses or multiple-account rotation.
- Record provider status such as `success`, `timeout`, `rate_limited`, `invalid_response`, or `error`.
- Never treat provider failure as a legitimate verdict.

**Deliverable:** isolated Gemini adapter, configuration example, mocked tests, and documented failure behavior.

### Day 5 — Combine evidence into one result
- Implement the detection orchestrator to run heuristics and available reputation/LLM checks through adapters.
- Combine evidence deterministically; do not let free-form LLM text directly determine the final label.
- Return `phishing`, `suspicious`, or `likely_legitimate` only when sufficient evidence exists.
- Use `analysis_status = complete | partial | unavailable`.
- If all meaningful checks fail, return `unavailable`, with a null risk score and no safe/legitimate claim.
- Include a concise explanation and a list of evidence items.

**Deliverable:** one function that returns the shared response contract for website/email inputs, with tests for complete, partial, and unavailable outcomes.

### Day 6 — Reputation adapter and input boundaries
- Integrate the reputation provider behind an adapter so the provider can be swapped.
- Respect provider terms, quotas, and privacy constraints.
- Add URL/domain normalization and strict input length/type limits.
- Do not implement arbitrary server-side URL fetching; avoid SSRF by limiting server requests to approved providers and fixed endpoints.
- Test provider errors and malformed responses.

**Deliverable:** reputation adapter with mocked tests and explicit tool status.

### Day 7 — Persistence and scan history
- Persist every scan as a new row, including repeated scans of the same domain.
- Save only minimized target reference, classification/score when available, structured evidence, tool statuses, source, and timestamps.
- Implement history queries with pagination and bounded result counts.
- Implement clear-history support only as agreed with Rohan; because the prototype has no authentication, keep it restricted to the trusted local environment and require explicit UI confirmation.
- Add a 30-day retention cleanup command/job and document how it is scheduled. A SQL delete statement alone does not schedule retention.

**Deliverable:** persistence integrated into the orchestrator and tested history/cleanup behavior.

### Day 8 — Connect detection to the backend contract
- Pair with Rohan to connect the detector/repository to the FastAPI routes.
- Verify website and email requests, validation errors, scan IDs, status fields, and history responses.
- Align the React popup with real response fields; do not hardcode a successful result.
- Confirm that API errors and timeouts produce clear partial/unavailable UI states.

**Deliverable:** working local request-to-result-to-database vertical slice.

### Day 9 — Build popup result UI
- Implement the product identity “Phishing Attack Detector” and the agreed editorial/quiet-security style.
- Show numeric risk score, classification, short explanation, evidence list, analysis completeness, and per-tool statuses.
- Use distinct layouts for phishing, suspicious, likely legitimate, partial, unavailable, loading, and API error states.
- Make the risk score understandable as a score, not a probability.
- Keep buttons and status messages accessible by keyboard and screen reader.

**Deliverable:** popup UI connected to API responses, including failure states.

### Day 10 — History and settings basics
- Add a simple scan history view with timestamp, domain, classification, and score where available.
- Add clear-history confirmation and a concise privacy/settings panel if these are in the agreed MVP.
- Ensure no API keys or sensitive full message/page content appear in frontend bundles, local storage, or logs.
- Check empty history, unavailable results, and long-domain layouts.

**Deliverable:** usable history/settings views and UI tests or documented manual checks.

### Day 11 — Test failure modes and security
- Test Gemini quota/rate limit, timeout, invalid JSON, empty response, and network failure.
- Test reputation-provider outage and partial results.
- Test database disconnect, malformed input, oversize input, and duplicate/repeated scans.
- Ensure prompt-injection text in page/email content is treated as untrusted data.
- Redact sensitive values from logs and avoid logging full email/page contents.
- Verify that failed checks never cause a “likely legitimate” result by default.

**Deliverable:** failure-mode checklist and regression tests.

### Day 12 — Docker and reproducible setup
- Create or refine Docker Compose for the API and PostgreSQL, using environment variables for secrets.
- Add `.env.example` with placeholders only; ensure `.env` and secrets are ignored by Git.
- Add database migration/setup commands and health checks.
- Write clear local setup, test, and troubleshooting commands.
- Verify startup from a clean clone or clean environment.

**Deliverable:** repeatable local startup with documented commands.

### Day 13 — CI and evaluation handoff
- Add automated lint/unit-test/build checks to CI where the repository supports it.
- Ensure tests can run without a real Gemini key by using mocks.
- Give Rohan stable sample requests/responses and test fixtures for evaluation.
- Review metrics from Rohan’s evaluation and help investigate false positives/false negatives.
- Fix high-impact issues before adding cosmetic polish.

**Deliverable:** passing automated checks and stable fixtures for evaluation.

### Day 14 — End-to-end regression and demo rehearsal
- Run the full path: popup → API → detector/adapters → database → response → history.
- Rehearse phishing, suspicious, likely-legitimate, partial, and unavailable examples.
- Verify extension/browser integration with Rohan.
- Prepare a short explanation of architecture, evidence combination, privacy, and known limitations.
- Freeze features; fix only release-blocking bugs.

**Deliverable:** demo-ready build and a short known-limitations list.

### Day 15 — Final verification and handoff
- Run all tests and a clean startup from documented instructions.
- Verify 30-day retention mechanism, clear-history confirmation, and secret handling.
- Confirm results do not claim certainty or safety beyond the available evidence.
- Finalize README sections for setup, architecture, API contract, testing, privacy, and limitations.
- Tag or archive the final demo-ready version and divide any remaining issues into must-fix versus future work.

**Deliverable:** reproducible demo, passing tests, documentation, and final handoff.

## 4. Definition of done

- [ ] Website and email scans return the agreed structured contract.
- [ ] Heuristics, Gemini, and reputation checks are isolated behind testable functions/adapters.
- [ ] LLM output is validated and treated as untrusted.
- [ ] Complete, partial, and unavailable outcomes are represented correctly.
- [ ] Provider failures never imply that a target is legitimate.
- [ ] Each scan is persisted as a new row with minimized metadata.
- [ ] History and clear-history behavior match the agreed contract.
- [ ] 30-day retention is actually scheduled/documented, not just represented by SQL.
- [ ] API keys remain server-side and are excluded from Git/frontend bundles/logs.
- [ ] Docker setup works from a clean environment.
- [ ] Tests cover success, edge cases, and provider/database failures.
- [ ] Popup communicates the verdict, score, evidence, and analysis limitations clearly.
- [ ] Rohan can run end-to-end evaluation using stable fixtures.

## 5. Daily coordination with Rohan

- Agree on API request/response fields by Day 2 and avoid independently renaming them.
- Share a working detector stub early so Rohan can build routes against a stable interface.
- Send Rohan sample fixtures for complete, partial, and unavailable scans.
- Integrate continuously from Day 5 onward; do not wait until the end to merge.
- Keep a shared issue list with owner, priority, reproduction steps, and status.
- Prioritize a complete vertical slice over polishing isolated modules.

## 6. Suggested implementation order

1. Shared contract and tests.
2. PostgreSQL repository.
3. Heuristics and provider adapters.
4. Evidence combination and analysis status.
5. End-to-end API integration.
6. Popup result UI and history.
7. Security/failure tests.
8. Docker, CI, docs, and demo rehearsal.

**Scope guard:** If time is short, deliver reliable website scanning and the full partial/unavailable handling first. Keep Gmail inline warning, richer settings, and visual polish secondary to a correct detection pipeline.
