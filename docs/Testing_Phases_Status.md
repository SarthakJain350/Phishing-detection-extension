# Testing Phases Status & Phase 5 Evaluation Plan

This document records the verified status of the structured testing campaign for the **Phishing Attack Detector** project, corrects historical testing records against available evidence, lists outstanding tests, and defines the Phase 5 Dataset Evaluation framework.

---

## 1. Corrected Testing Phases Status (Phases 1–4)

> **Important Note on Test Counts:**
> The overall test-suite totals are **315 passing backend tests** and **122 passing extension tests** (with TypeScript type-check and Vite production build both clean). These figures represent entire regression test-suite runs, **not** individual phase-specific counts. Individual phase counts are marked as **Not isolated / Unverified** because test execution was performed against broad suites and manual verification protocols without dedicated phase-tagged test subsets.

| Phase | Description & Verified Scope | Status | Evidence & Observations | Phase Test Count |
| :--- | :--- | :--- | :--- | :--- |
| **Phase 1** | **Database Privacy & Persistence** | ✅ **PASSED** | Inspected PostgreSQL database records and schema; confirmed no raw email body, subject, or sensitive sender content was stored in inspected scan records.<br>*(Note: Encryption at rest was NOT separately confirmed or tested and is not claimed).* | *Not isolated / unverified* |
| **Phase 2** | **Backend-Down and Recovery Behavior** | ✅ **PASSED** | Tested extension resilience and user feedback when backend services are unreachable, offline, or recovering from failure states. | *Not isolated / unverified* |
| **Phase 3** | **Rapid Duplicate Gmail Scan Prevention** | ✅ **PASSED** | Verified that repeated rapid user clicks on the "Scan Email" button do not trigger duplicate concurrent backend scans or corrupt state. | *Not isolated / unverified* |
| **Phase 4** | **Website Regression & Provider Behavior** | ⚠️ **PASSED (with limitation)** | Website regression tests passed on retest. However, intermittent Gemini timeout/unavailable behavior was observed (`analysis_status="unavailable"`). Root cause is not yet established. | *Not isolated / unverified* |

### Latest Full Test Suite Verification Results
- **Backend Test Suite:** `315 passed` (`pytest backend/tests/ -q`)
- **Extension Test Suite:** `122 passed` across 25 suites (`npm --prefix extension test`)
  - `tests/warning_integration.test.ts`: 25 passed (5 suites)
  - `tests/status_formatting.test.ts`: 31 passed (7 suites)
  - `tests/history_navigation.test.ts`: 14 passed (3 suites)
  - `tests/gmail_background.test.ts`: 16 passed (2 suites)
  - `spikes/tests/test_spikes.cjs`: 36 passed (8 suites)
- **Extension TypeScript Type-Check:** `passed` (`npx tsc --noEmit`)
- **Extension Production Build:** `passed` (`npm run build`, producing clean `dist/`)

---

## 2. Outstanding & Unverified Tests

The following tests remain outstanding and must stay visible for future verification:

1. **Gmail Multi-Message Selection:** Verify extraction behavior and error handling when multiple messages are selected simultaneously in the Gmail thread view.
2. **Backend Concurrency Stress Testing:** Evaluate backend performance and database connection pooling under high simultaneous scan loads.
3. **Phase 4 Timeout Root-Cause Investigation:** Investigate the intermittent Gemini timeout/unavailable outcome (including evaluating whether `_TOTAL_TIMEOUT_SECONDS = 8.0` requires tuning or adaptive retry).
4. **End-to-End Privacy Regression:** Verify across the entire pipeline that full email links containing sensitive tokens or query parameters are never persisted or displayed, even under partial provider errors.
5. **Cross-Platform UI Validation:** Validate Chrome extension layout, popup rendering, and interstitial warning flows across Linux and macOS environments.

---

## 3. Phase 5 — Dataset Evaluation Scaffolding

### Objective
Provide a reproducible, 100% offline dataset evaluation pipeline to benchmark detection heuristics on real-world phishing and legitimate datasets without live network calls, Gemini API usage, or reputation provider queries.

### Candidate Dataset Sources, Citations & License Verification

| Dataset | Nature / Content | Official Source & Reference | Terms / License & Verification Date |
| :--- | :--- | :--- | :--- |
| **PhishTank** | Verified community-submitted phishing URLs | [PhishTank Developer Info](https://www.phishtank.com/developer_info.php) (Cisco Talos) | **Developer Terms of Use:** Free for non-commercial and academic evaluation with mandatory attribution: *"Data provided by PhishTank"*. Commercial use requires explicit approval. Download rate limits apply without an API application key.<br>*Verified: November 2026.* |
| **URLhaus** | Malware distribution URLs & payloads | [abuse.ch URLhaus Project](https://urlhaus.abuse.ch/api/) | **License:** Creative Commons Zero 1.0 (CC0) Public Domain.<br>**Important Limitation:** URLhaus tracks malware distribution sites, payload drops (`.exe`, `.sh`, `.dll`), and C2 endpoints, **not exclusively phishing URLs**. Malicious records must be tagged by threat type (`malware_download` vs `phishing`).<br>*Verified: November 2026.* |
| **OpenPhish** | Automated phishing intelligence feed | [OpenPhish Community Feed](https://openphish.com/terms.html) | **Terms of Service:** Free Community Feed is permitted for non-commercial research and personal evaluation. Redistribution and commercial reuse are prohibited without a paid commercial license.<br>*Verified: November 2026.* *(Note: Specific redistribution rights for bundled test sets are unverified and require maintaining local raw caches rather than committing raw dumps).* |
| **Tranco Top Sites** | High-traffic legitimate domains | [Tranco List](https://tranco-list.eu/)<br>Reference: Le Pochat et al., NDSS 2019 | **License:** Creative Commons Attribution 4.0 International (CC-BY-4.0).<br>Research-oriented ranking list replacing the deprecated Alexa Top-1M. Formatted with `https://<domain>/` for benign targets.<br>*Verified: November 2026.* |

> **Prohibited Sources:** The obsolete and proprietary **Alexa Top-1K** (sunset by Amazon on May 1, 2022) is strictly excluded.

### Evaluation Methodology & Binary Metrics
1. **Offline Execution:** Zero network calls, zero live page fetching, zero Gemini API usage, and zero live Safe Browsing queries.
2. **Transparent Inconclusive Outcome Handling:**
   - In offline mode, clean legitimate URLs have zero heuristic findings and produce `classification=None`, `risk_score=None`, and `analysis_status="partial"`.
   - Inconclusive results are **never** silently classified as phishing.
   - The evaluation framework reports **Coverage** alongside all metrics:
     $$\text{Coverage Rate} = \frac{\text{Conclusive Scans}}{\text{Total Samples}} \times 100\%$$
3. **Explicit Multi-Policy Reporting:**
   - **Policy A (High-Confidence Phishing Alert):** Positive = `classification == "phishing"` (score $\ge 70$).
   - **Policy B (Actionable Threat Warning):** Positive = `classification in ("phishing", "suspicious")`.
   - **Policy C (Conclusive-Only Subset):** Evaluated strictly on samples where a classification was produced, reporting the exact coverage percentage.

---

## 4. Scaffold Files Created

- `evaluation/requirements.txt`: Python dependencies (`pydantic`, `tldextract`).
- `evaluation/prepare_dataset.py`: Normalization, deduplication, threat-type tagging, and provenance tracking.
- `evaluation/evaluate.py`: Offline deterministic evaluation engine and metrics reporter.
- `evaluation/README.md`: Guide to dataset sources, licensing, and methodology.
- `docs/Testing_Phases_Status.md`: This document.
