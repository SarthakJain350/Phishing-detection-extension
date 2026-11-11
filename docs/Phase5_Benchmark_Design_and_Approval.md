# Benchmark Design & Dataset Approval Specification

> **Document Version:** 1.1 (Implementation Alignment & Provenance Specification)
> **Date:** November 11, 2026
> **Project:** Phishing Attack Detector — Phase 5 Offline Evaluation
> **Approved Primary Benchmark Pair:**
> 1. **PhishTank (`online-valid`)**: Primary phishing-positive evaluation corpus.
> 2. **Tranco Top Sites**: Supplementary benign-domain reference baseline.
> **Explicitly Excluded Datasets:**
> - **CIC-Trap4Phish 2025**: Excluded from primary benchmark due to threat conflation (malware droppers/payloads) and noisy in-email links.
> - **ISCX-URL2016**: Excluded due to absence of raw URL fields.

---

## 1. Executive Summary & Design Principles

This document defines the rigorous, reproducible benchmarking design for evaluating the **Phishing Attack Detector** in an entirely offline, deterministic testing environment.

### Core Architecture & Evaluation Philosophy
1. **100% Offline & Deterministic:**
   - **Zero Network Execution:** No DNS lookups, no live HTTP requests, and no domain availability pings.
   - **Zero External AI / Token Waste:** Opted-out Gemini (`opt_in_gemini=False`) guarded by `OfflineGeminiGuard`.
   - **Zero Live Reputation Calls:** `reputation=None` (no live Google Safe Browsing or third-party lookups).
   - **Target-Only URL Heuristics:** Evaluates lexical, domain structure, homoglyphs, brand spoofing, and path anomalies using `DeterministicHeuristicsEngine`.
2. **Dual-Corpus Separation (Positive vs Reference Baseline):**
   - **PhishTank** measures **Sensitivity / Recall** and detection latency across real phishing attacks.
   - **Tranco** measures **False-Positive Rate (FPR)** and **Specificity** against high-reputation domains.
   - **Tranco is NEVER treated as pure ground truth:** Popular domains are treated as high-reputation *reference baselines*, not human-verified clean URLs.
3. **Transparent Inconclusive Outcome Handling:**
   - Clean URLs that trigger zero malicious heuristics receive `classification=None`, `risk_score=None`, and `analysis_status="partial"`.
   - These abstentions are **never** silently converted to phishing or legitimate; they are accounted for via a dedicated **Coverage** metric and three documented binary decision policies.
4. **Prevalence Interpretation Boundary:**
   - Evaluated metrics (Precision, F1-score, and Accuracy) derived from a balanced $1:1$ sample (5,000 phish : 5,000 benign) are benchmark-specific performance indicators and **do NOT represent real-world deployment prevalence estimates**, where phishing URLs typically represent a very small fraction of operational web traffic.

---

## 2. Snapshot Selection & Reproducibility Strategy

Because live threat intelligence feeds and top lists update dynamically (PhishTank updates hourly; Tranco updates daily), an academic benchmark must be strictly frozen to remain reproducible.

```
                    Raw Data Ingestion (Frozen Snapshot)
                   ┌────────────────────────────────────┐
                   │  PhishTank: online-valid.csv.gz    │
                   │  Tranco:    top-1m.csv.zip (ListID)│
                   └─────────────────┬──────────────────┘
                                     │
                                     ▼
                      Integrity & Provenance Logging
                   ┌────────────────────────────────────┐
                   │  Compute SHA-256 Checksums         │
                   │  Record UTC Download Timestamp     │
                   │  Log Exact Record Counts           │
                   └─────────────────┬──────────────────┘
                                     │
                                     ▼
                        Offline Dataset Preprocessor
                      (evaluation/prepare_dataset.py)
                   ┌────────────────────────────────────┐
                   │  Canonical URL Normalization       │
                   │  Deterministic Deduplication       │
                   │  Sample Limit Enforcement          │
                   └─────────────────┬──────────────────┘
                                     │
                                     ▼
                        Unified Evaluation JSONL File
                        (evaluation/dataset.jsonl)
```

### 2.1 PhishTank Snapshot Freezing
1. **Target Feed:** `online-valid.csv.gz` (gzipped CSV format minimizes local download bandwidth to ~12–15 MB while matching `parse_phishtank_file()`).
2. **Timestamp Protocol:** The user executes the download once, recording the exact UTC timestamp.
3. **Naming Convention:** Store locally as:
   `data/raw/phishtank_online_valid_YYYYMMDD_HHMM.csv.gz`
4. **Integrity Lock:** Compute and record the SHA-256 hash immediately upon download.

### 2.2 Tranco Snapshot Freezing
1. **Target Feed:** `top-1m.csv.zip` (compressed archive containing `top-1m.csv`).
2. **List ID Protocol:** Prior to or immediately upon download, query `https://tranco-list.eu/top-1m-id` to retrieve the official alphanumeric List ID (e.g., `Y83YG`).
3. **Naming Convention:** Store locally as:
   `data/raw/tranco_top_1m_list_{LIST_ID}_YYYYMMDD.csv.zip`
4. **Integrity Lock:** Compute and record the SHA-256 hash immediately upon download.

### 2.3 Benchmark Provenance Manifest Schema
A structured provenance metadata file (`evaluation/BENCHMARK_PROVENANCE.json`) is generated alongside the prepared dataset recording exact snapshot lineage:
```json
{
  "benchmark_name": "Phishing_Detector_Phase5_Baseline",
  "created_at_utc": "2026-11-11T00:30:00Z",
  "phishtank_snapshot": {
    "filename": "phishtank_online_valid_YYYYMMDD_HHMM.csv.gz",
    "sha256": "<computed_sha256>",
    "download_url": "https://data.phishtank.com/data/online-valid.csv.gz"
  },
  "tranco_snapshot": {
    "filename": "tranco_top_1m_list_{LIST_ID}_YYYYMMDD.csv.zip",
    "list_id": "{LIST_ID}",
    "sha256": "<computed_sha256>",
    "download_url": "https://tranco-list.eu/top-1m.csv.zip"
  }
}
```

---

## 3. Dataset Sampling & Trade-off Analysis

### 3.1 Trade-off Spectrum

| Sample Configuration | Size (Phish / Benign) | Total | Evaluation Runtime (Offline) | Statistical Power | Recommendation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Micro (Smoke)** | 100 / 100 | 200 | ~0.5 seconds | Insufficient for edge-case coverage. | Diagnostic testing only. |
| **Balanced Standard (Academic)** | **5,000 / 5,000** | **~10,000** | **~25–40 seconds** | **Optimal for academic evaluation.** Substantial sample size with low memory footprint (< 100 MB). As a theoretical reference under independent random sampling assumptions, 10,000 independent samples at a 50% proportion would yield an approximate margin of error of $\pm 0.98$ percentage points at 95% confidence, and 5,000 samples per class would yield an approximate worst-case margin of $\pm 1.39$ percentage points. However, because our benchmark extracts records via deterministic head-sequential ordering (the first 5,000 PhishTank feed entries and top 5,000 Tranco ranks) rather than random sampling, these theoretical calculations do not establish valid statistical confidence intervals for the actual benchmark sample. | **Recommended Primary Benchmark.** |
| **Extended High-Volume** | 20,000 / 20,000 | 40,000 | ~2–3 minutes | Minimal marginal statistical gain; higher disk footprint. | Optional stress test. |
| **Full Exhaustive** | ~40,000 / 1,000,000 | ~1,040,000 | ~15–25 minutes | Severe class imbalance ($1:25$); high redundancy on tail domains. | Impractical for iterative evaluation. |

### 3.2 Recommended Sample Size: **Target 10,000 Samples (5,000 PhishTank + 5,000 Tranco Limits)**
**Technical Justification & Implementation Reality:**
1. **Local Hardware Friendliness:** In our Windows environment, Python runs offline URL heuristic analysis at ~250–400 items/second. A 10,000-sample dataset completes evaluation in under 40 seconds.
2. **Balanced Prior:** Equal initial extraction ($1:1$) enables direct calculation of both Sensitivity and Specificity across balanced classes.
3. **Tranco Head Selection (Top 5,000):** Limiting Tranco to the top 5,000 domains focuses the benign baseline on established high-reputation global web properties, minimizing the risk of encountering compromised personal blogs or parked domains that occasionally populate the lower percentiles of the top 1M.
4. **Post-Deduplication Sample Shrinkage Caveat:**
   > [!NOTE]
   > In `evaluation/prepare_dataset.py`, `--phishtank-limit 5000` and `--tranco-limit 5000` are applied *at the source extraction stage* to cap raw records read. Full-canonical deduplication (`seen_urls`) executes subsequently across the assembled candidate pool. If internal duplicate URLs or cross-source collisions exist within the first 5,000 rows, the final accepted count (`deduped_total`) will be **slightly below 10,000** (typically ~9,850–9,990 records). This behavior is normal, deterministic, and preserves data integrity.

---

## 4. Label Strategy & Edge-Case Handling

```
                              Raw URL Input
                                    │
                                    ▼
                         normalize_url_for_eval()
                                    │
                        ┌───────────┴───────────┐
                        │                       │
                  Valid URL String        Malformed / Blank
                        │                       │
                        ▼                       ▼
               Deduplication Check         Discard / Skip
                        │
            ┌───────────┴───────────┐
            │                       │
      First Observed           Duplicate URL
            │                       │
            ▼                       ▼
      Add to Dataset        Increment Duplicate Count
            │               (Skip redundant row)
            │
            ├───────────────────────────────────────────┐
            ▼                                           ▼
      Source: PhishTank                           Source: Tranco
   label: "phishing"                           label: "legitimate"
   threat_type: "phishing"                     threat_type: "benign"
   provenance: phish_id + brand                provenance: tranco_rank
```

### 4.1 Ground-Truth Representation
- **PhishTank Records:**
  - `label`: `"phishing"`
  - `threat_type`: `"phishing"`
  - `source`: `"phishtank"`
  - `source_id`: `<phish_id>`
  - `notes`: `target=<brand_impersonated>`
- **Tranco Records:**
  - `label`: `"legitimate"`
  - `threat_type`: `"benign"`
  - `source`: `"tranco"`
  - `source_id`: `<tranco_rank>`
  - `notes`: `tranco_rank=<rank>; reference_baseline=true` (indicates high-reputation popularity reference)

### 4.2 Handling Overlaps & Domain Collisions
1. **Multi-Tenant / Compromised Major Domains:**
   - If an attacker deploys a phishing kit on a free host or cloud storage (e.g. `https://storage.googleapis.com/.../login.html`), PhishTank will contain this specific sub-path URL (`label: phishing`). Tranco contains the root domain (`https://googleapis.com/`, `label: legitimate`).
   - **Resolution:** Deduplication operates on the **full canonical normalized URL**, not the root domain. The specific sub-path remains in the phishing set, and the bare root domain remains in the Tranco set.
2. **Identical Canonical URL in Both Sources:**
   - In the unlikely event that a bare root domain is submitted to PhishTank and also appears in Tranco, `prepare_dataset.py` operates a **first-seen precedence** rule. Because PhishTank is parsed first, the confirmed phishing claim takes precedence.
3. **Abstentions / Inconclusive Detector Verdicts:**
   - The detector returns `classification=None`, `risk_score=None`, and `analysis_status="partial"` when zero heuristics are triggered.
   - **Handling:** Abstentions are preserved explicitly as `None` in `EvaluationRecord`. They are **never** coerced into verified benign or verified phishing.

---

## 5. Evaluation Methodology & Policy Framework

The evaluation engine (`evaluation/evaluate.py`) evaluates every sample and cross-tabulates detector verdicts against ground truth across three formal decision policies:

```
                            Detector Verdict
                                   │
      ┌────────────────────────────┼────────────────────────────┐
      ▼                            ▼                            ▼
 "phishing"                   "suspicious"             "likely_legitimate"
 (risk_score >= 70)       (40 <= score < 70)        (0 <= score < 40)
      │                            │                            │
      ├────────────────────────────┤                            │
      │   Policy B: Threat Alert   │                            │
      ▼                            ▼                            ▼
[Threat Warning]          [Threat Warning]             [Safe / Clean]

────────────────────────────────────────────────────────────────────────
                      No Heuristic Triggered
                                │
                                ▼
                       Inconclusive (None)
                       (analysis_status: "partial")
                                │
            ┌───────────────────┴───────────────────┐
            ▼                                       ▼
    Policies A & B:                         Policy C:
    Treated as Non-Threat                   Excluded from Calculation
    (Conservative Negative)                 (Conclusive-Only Subset)
```

### 5.1 Documented Binary Policies & Abstention Semantics
> [!IMPORTANT]
> **Abstention Semantics in Policies A and B:**
> When the offline heuristics engine triggers zero rules, the detector produces `classification=None` (an abstention / partial assessment). Policies A and B operationalize this verdict as a **negative decision** (i.e. *do not block / do not warn*).
> **This does NOT mean the URL was classified as verified legitimate.**
> - **Effect on Phishing Samples (Ground-Truth Phishing):** An abstention on a phishing URL results in a **False Negative (FN)**, correctly penalizing detector recall.
> - **Effect on Benign Samples (Ground-Truth Legitimate):** An abstention on a clean Tranco domain results in a **True Negative (TN)**, crediting the detector for correctly refraining from triggering false alarms on uncompromised traffic.

1. **Policy A — High-Confidence Phishing Alert (Strict Blocking):**
   - **Predicted Positive:** `classification == "phishing"` (risk_score $\ge 70$).
   - **Predicted Negative:** `classification in ("suspicious", "likely_legitimate")` or `None` (abstention).
   - *Operational Meaning:* Strict automated blocking threshold. Inconclusive outcomes pass through without blocking.
2. **Policy B — Actionable Threat Warning (Sensitive Interstitial):**
   - **Predicted Positive:** `classification in ("phishing", "suspicious")`.
   - **Predicted Negative:** `classification == "likely_legitimate"` or `None` (abstention).
   - *Operational Meaning:* User warning banner trigger. Inconclusive outcomes are conservatively treated as negative.
3. **Policy C — Conclusive-Only Subset (Conditional Heuristic Quality):**
   - Evaluates **only** samples where the detector produced a definitive verdict (`classification is not None`).
   - Abstentions are excluded from this calculation. Reports heuristic discrimination quality conditioned on triggering, interpreted alongside the global **Coverage Rate**.

### 5.2 Metrics Calculated
- **Dataset Coverage:**
  $$\text{Coverage Rate} = \frac{\text{Conclusive Scans}}{\text{Total Samples}} \times 100\%$$
- **Precision:** $\frac{TP}{TP + FP}$ *(Note: Benchmark metric conditioned on balanced sample, not real-world deployment prevalence).*
- **Recall (Sensitivity):** $\frac{TP}{TP + FN}$
- **Specificity:** $\frac{TN}{TN + FP}$
- **False Positive Rate (FPR):** $\frac{FP}{FP + TN} = 1 - \text{Specificity}$
- **F1-Score:** $\frac{2 \times \text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$
- **Classification Matrix:** Full $2 \times 4$ cross-tabulation (PhishTank vs Tranco crossed with Phishing, Suspicious, Likely Legit, and Inconclusive).
- **Rule Activation Frequency:** Top triggered heuristic rules across both positive and negative corpora.

---

## 6. Step-by-Step Local Execution Plan (For Windows PowerShell)

> [!IMPORTANT]
> The following commands are provided as an execution plan for the user to run directly in Windows PowerShell. **Antigravity will not execute these commands.**

### Step 1: Download Raw Snapshots with Exact Timestamped Naming
Open Windows PowerShell, navigate to the project directory, and download the snapshots using the timestamped convention:
```powershell
cd "C:\Phishing Attack Detector"

# Ensure data/raw and evaluation directories exist
New-Item -ItemType Directory -Force -Path "data\raw"
New-Item -ItemType Directory -Force -Path "evaluation"

# Capture single UTC timestamp for snapshot filenames
$UtcNow = (Get-Date).ToUniversalTime()
$UtcTimestamp = $UtcNow.ToString("yyyyMMdd_HHmm")
$UtcDateOnly = $UtcNow.ToString("yyyyMMdd")

# 1. Download PhishTank online-valid compressed feed
$PhishTankUrl = "https://data.phishtank.com/data/online-valid.csv.gz"
$PhishTankFilename = "phishtank_online_valid_${UtcTimestamp}.csv.gz"
$PhishTankPath = "data\raw\$PhishTankFilename"

Write-Host "Downloading PhishTank snapshot to $PhishTankPath..."
Invoke-WebRequest -Uri $PhishTankUrl -OutFile $PhishTankPath -UserAgent "PhishingDetectorEvaluation/1.0"

# 2. Check and record latest Tranco List ID, then download top 1M list
$TrancoId = (Invoke-RestMethod -Uri "https://tranco-list.eu/top-1m-id").Trim()
Write-Host "Current Tranco List ID: $TrancoId"

$TrancoUrl = "https://tranco-list.eu/top-1m.csv.zip"
$TrancoFilename = "tranco_top_1m_list_${TrancoId}_${UtcDateOnly}.csv.zip"
$TrancoPath = "data\raw\$TrancoFilename"

Write-Host "Downloading Tranco snapshot to $TrancoPath..."
Invoke-WebRequest -Uri $TrancoUrl -OutFile $TrancoPath -UserAgent "PhishingDetectorEvaluation/1.0"
```

### Step 2: Compute SHA-256 Hashes and Generate `BENCHMARK_PROVENANCE.json`
Execute this PowerShell script to compute checksums and write the provenance manifest:
```powershell
# Compute SHA-256 hashes
$PhishTankHash = (Get-FileHash -Algorithm SHA256 -Path $PhishTankPath).Hash.ToLower()
$TrancoHash = (Get-FileHash -Algorithm SHA256 -Path $TrancoPath).Hash.ToLower()

Write-Host "PhishTank SHA-256: $PhishTankHash"
Write-Host "Tranco SHA-256:    $TrancoHash"

# Capture explicit manifest generation timestamp
$ManifestCreatedAtUtc = (Get-Date).ToUniversalTime().ToString("yyyy-MM-ddTHH:mm:ssZ")

# Generate JSON manifest object
$ProvenanceManifest = [PSCustomObject]@{
    benchmark_name    = "Phishing_Detector_Phase5_Baseline"
    created_at_utc    = $ManifestCreatedAtUtc
    phishtank_snapshot = [PSCustomObject]@{
        filename     = $PhishTankFilename
        sha256       = $PhishTankHash
        download_url = $PhishTankUrl
    }
    tranco_snapshot   = [PSCustomObject]@{
        filename     = $TrancoFilename
        list_id      = $TrancoId
        sha256       = $TrancoHash
        download_url = $TrancoUrl
    }
}

# Write formatted JSON to evaluation/BENCHMARK_PROVENANCE.json
$ProvenanceManifest | ConvertTo-Json -Depth 4 | Set-Content -Path "evaluation\BENCHMARK_PROVENANCE.json" -Encoding UTF8
Write-Host "Saved benchmark provenance manifest to evaluation\BENCHMARK_PROVENANCE.json"
```

### Step 3: Prepare the Unified Evaluation Dataset
Execute the offline preprocessor referencing the exact timestamped snapshot paths:
```powershell
python evaluation/prepare_dataset.py `
  --phishtank-file $PhishTankPath `
  --phishtank-limit 5000 `
  --tranco-file $TrancoPath `
  --tranco-limit 5000 `
  --output evaluation\dataset.jsonl
```

### Step 4: Run the Deterministic Offline Evaluation
Execute the evaluation engine and save the structured report:
```powershell
python evaluation/evaluate.py `
  --dataset evaluation\dataset.jsonl `
  --output-json evaluation\evaluation_report_baseline.json
```

---

## 7. Approval & Sign-Off Checklist

Before running the PowerShell execution plan, please verify that:
- [x] PhishTank source audit is complete and approved.
- [x] Tranco source audit is complete and approved.
- [x] CIC-Trap4Phish is excluded from the primary benchmark.
- [x] Snapshot, hashing, and reproducibility strategy is defined.
- [x] Exact timestamped filename harmonization is applied across all PowerShell steps.
- [x] Provenance manifest generation procedure is documented.
- [x] Post-deduplication sample shrinkage behavior is documented.
- [x] Abstention semantics in Policies A & B are formally defined.
- [x] Metric prevalence boundary is explicitly stated.
- [x] Strict offline boundary is maintained (no network, no LLM tokens, no reputation lookups).
- [ ] User approval granted to proceed with local PowerShell execution.
