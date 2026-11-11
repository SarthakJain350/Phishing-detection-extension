# Phase 5 — Dataset Evaluation Scaffolding

This directory contains the reproducible, offline evaluation framework for evaluating the **Phishing Attack Detector** against curated phishing and legitimate URL datasets.

---

## 1. Principles & Safety Boundaries

The evaluation runner (`evaluate.py`) and dataset preprocessor (`prepare_dataset.py`) strictly adhere to the following constraints:

1. **100% Offline Execution:**
   - **No live page fetching or URL visits:** Detection is evaluated strictly from URL strings and domain structures via `DeterministicHeuristicsEngine`.
   - **No Gemini API calls:** Runs with `opt_in_gemini=False` and unconfigured LLM adapters. No external AI tokens are spent or network calls made.
   - **No live reputation provider lookups:** Safe Browsing and third-party reputation lookups are disabled (`reputation=None`).
   - **Zero credential exposure:** No API keys, passwords, or `.env` secrets are required, accessed, or printed.
2. **Deterministic & Reproducible:**
   - Evaluates targets through `RealDetectionOrchestrator._combine()` with standard offline domain extraction (`backend.app.core.domain.extract_domain_info`).
   - Detection heuristics, thresholds, and scoring rules are untouched.
3. **No Silent Mapping of Inconclusive Outcomes:**
   - The detector legitimately returns `classification=None`, `risk_score=None`, and `analysis_status="partial"` when deterministic heuristics find zero indicators and external services are opted out or unintegrated.
   - Inconclusive results are **never** silently treated as phishing. They are reported explicitly and tracked via a **Coverage** metric.

---

## 2. Dataset Sources, Citations & License Verification

To maintain data provenance and strictly comply with usage terms, candidate datasets are reviewed below:

| Dataset | Type / Content | Official Source & Reference | Terms / License & Verification Date |
| :--- | :--- | :--- | :--- |
| **PhishTank** | Verified community-submitted phishing URLs | [PhishTank Developer Portal](https://www.phishtank.com/developer_info.php) (Cisco Talos) | **Developer Terms of Use:** Free for non-commercial and academic evaluation with mandatory attribution: *"Data provided by PhishTank"*. Commercial use requires explicit approval. Download rate limits apply without an API application key.<br>*Verified: November 2026.* |
| **URLhaus** | Malware distribution URLs & payloads | [abuse.ch URLhaus API](https://urlhaus.abuse.ch/api/) | **License:** Creative Commons Zero 1.0 (CC0) Public Domain.<br>**Important Limitation:** URLhaus tracks malware distribution sites, payload drops (`.exe`, `.sh`, `.dll`), and C2 endpoints, **not exclusively phishing URLs**. Malicious records are tagged by threat type (`malware_download` vs `phishing`).<br>*Verified: November 2026.* |
| **OpenPhish** | Automated phishing intelligence feed | [OpenPhish Community Feed](https://openphish.com/terms.html) | **Terms of Service:** Free Community Feed is permitted for non-commercial research and personal evaluation with attribution. Redistribution and commercial reuse are prohibited without a paid commercial license.<br>*Verified: November 2026.* *(Note: Specific redistribution rights for bundled test sets are unverified and require maintaining local raw caches rather than committing raw dumps).* |
| **Tranco Top Sites** | High-traffic legitimate domains | [Tranco Research List](https://tranco-list.eu/)<br>Reference: Le Pochat et al., NDSS 2019 | **License:** Creative Commons Attribution 4.0 International (CC-BY-4.0).<br>Research-oriented ranking list created as a reproducible successor to the retired/proprietary Alexa Top-1M. Domains are formatted as `https://<domain>/`. Attribution to Tranco research paper required.<br>*Verified: November 2026.* |

> **Prohibited Sources:** The obsolete and proprietary **Alexa Top-1K** (sunset by Amazon on May 1, 2022) is strictly excluded. Tranco is used exclusively for legitimate baseline domains.

---

## 3. Data Format & Provenance Schema

`prepare_dataset.py` formats raw inputs into a unified JSONL file with explicit metadata:

```json
{
  "url": "https://paypal.com.account-update.xyz/login",
  "normalized_url": "https://paypal.com.account-update.xyz/login",
  "label": "phishing",
  "source": "phishtank",
  "source_id": "8123456",
  "collection_date": "2026-11-10T14:30:00Z",
  "threat_type": "phishing",
  "notes": "Target: PayPal"
}
```

- **Deduplication:** Normalizes URLs to standard scheme, lowercase netloc, and consistent paths. Duplicate occurrences are stripped while recording count statistics.
- **Labels:** Explicit ground-truth labels: `"phishing"` or `"legitimate"` (or `"malware_url"`).

---

## 4. Evaluation Methodology & Binary Policies

The detector classifies scans into three tiers:
- `"phishing"` (risk_score >= 70)
- `"suspicious"` (risk_score >= 40 or heuristic evidence found)
- `"likely_legitimate"` (clean with low risk)
- `None` (inconclusive / partial assessment when heuristics find zero indicators and external providers are disabled)

Because our offline evaluation operates without live content or external reputation checks, clean legitimate domains produce inconclusive partial outcomes. To avoid distorted or deceptive metrics, the evaluation script reports:

1. **Overall Dataset Coverage:**
   $$\text{Coverage Rate} = \frac{\text{Conclusive Scans (classification } \neq \text{ null)}}{\text{Total Evaluated Samples}} \times 100\%$$

2. **Full Classification Matrix:**
   Cross-tabulation of ground truth (`phishing`, `legitimate`) against all detector outcomes (`phishing`, `suspicious`, `likely_legitimate`, `inconclusive`).

3. **Three Documented Binary Policies:**
   - **Policy A — High-Confidence Phishing Alert:**
     - Predicted Positive: `classification == "phishing"` (score $\ge 70$).
     - Predicted Negative: `classification in ("suspicious", "likely_legitimate")` or inconclusive.
     - *Represents strict blocking with minimal false alarms.*
   - **Policy B — Actionable Threat Warning (Sensitive):**
     - Predicted Positive: `classification in ("phishing", "suspicious")`.
     - Predicted Negative: `classification == "likely_legitimate"` or inconclusive.
     - *Represents triggering a user warning interstitial. Inconclusive outcomes are conservatively treated as negative.*
   - **Policy C — Conclusive-Only Subset:**
     - Evaluated **only** on samples where the detector produced a conclusive verdict.
     - *Evaluates the discrimination quality of triggered heuristics while explicitly citing dataset coverage.*

---

## 5. Quickstart & Smoke Testing

### Running the Offline Smoke Test
Run an end-to-end evaluation on the built-in synthetic smoke test samples:

```powershell
python evaluation/evaluate.py --smoke-test
```

### Generating a Sample Dataset File & Evaluating
```powershell
# 1. Generate smoke test dataset file
python evaluation/prepare_dataset.py --smoke-test --output evaluation/smoke_test_dataset.jsonl

# 2. Run evaluation against the dataset file
python evaluation/evaluate.py --dataset evaluation/smoke_test_dataset.jsonl --output-json evaluation/smoke_test_report.json
```

### Preparing Real Datasets
Once raw snapshots are downloaded locally (e.g., into `data/raw/`), prepare the dataset using:
```powershell
python evaluation/prepare_dataset.py `
  --phishtank-file data/raw/phishtank_online_valid.csv.gz `
  --phishtank-limit 5000 `
  --tranco-file data/raw/tranco_top_1m.csv.zip `
  --tranco-limit 5000 `
  --output evaluation/dataset.jsonl
```

---

## 6. Baseline Offline Evaluation Results (PhishTank / Tranco Benchmark)

The initial deterministic baseline was evaluated against a balanced snapshot combining **PhishTank** (`online-valid`) and **Tranco Top Sites** (head 5,000 domains). Source provenance and exact SHA-256 hashes are recorded in `evaluation/BENCHMARK_PROVENANCE.json`, and raw output metrics reside in `evaluation/evaluation_report_baseline.json`.

### 6.1 Benchmark Nature & Important Baseline Limitations
1. **Tranco Reference Baseline Role:** Tranco provides popular domain rankings, **not verified-safe ground truth**. It serves as a high-reputation reference baseline specifically to assess false-alarm behavior on major domains.
2. **Deterministic Heuristics Scope (Coverage & Recall Limitations):**
   - **Coverage Rate: 7.54% (753 / 9,984 samples).** 92.46% of all evaluated URLs possessed zero structural or lexical anomalies and produced no heuristic triggers.
   - **Policy B Recall: 14.97% (746 / 4,984 phishing samples).** Offline URL heuristics alone detect roughly 1 in 6.7 phishing URLs. The remaining 85.03% use standard domain paths or uncompromised structures requiring content inspection or reputation feeds.
3. **Abstentions vs. Verified Legitimate Classifications:**
   - When heuristics find zero indicators without reputation or LLM analysis, the engine produces `classification=None` and `analysis_status="partial"`.
   - **Abstaining is NOT a proof of safety.** In operational policies (Policies A and B), an abstention represents a negative decision (*"no warning banner generated"*), distinct from a positive *"classified as legitimate"* verdict.
4. **Prevalence Boundary:** The **99.07% Policy B precision** and **99.86% specificity** are performance metrics conditioned on this balanced $1:1$ benchmark test set and **do not constitute operational deployment estimates**, where real-world phishing traffic prevalence is far lower.

### 6.2 Evaluated Performance Metrics

| Metric | Policy A (High-Confidence Alert) | Policy B (Actionable Threat Warning) | Policy C (Conclusive-Only Subset) |
| :--- | :--- | :--- | :--- |
| **Operational Rule** | `classification == "phishing"` (score $\ge 70$) | `classification in ("phishing", "suspicious")` | `classification in ("phishing", "suspicious")` |
| **Evaluated Cohort** | All samples ($N = 9,984$) | All samples ($N = 9,984$) | Conclusive only ($N = 753$; **7.54% coverage**) |
| **True Positives (TP)** | 26 | 746 | 746 |
| **False Positives (FP)** | 4 | 7 | 7 |
| **True Negatives (TN)** | 4,996 (4,993 abstentions + 3 suspicious) | 4,993 (all abstentions) | 0 |
| **False Negatives (FN)**| 4,958 (4,238 abstentions + 720 suspicious)| 4,238 (all abstentions) | 0 |
| **Precision** | **86.67%** | **99.07%** | **99.07%** |
| **Recall (Sensitivity)**| **0.52%** | **14.97%** | **100.00%** |
| **Specificity** | **99.92%** | **99.86%** | **0.00%** *(see note below)* |
| **False Positive Rate** | **0.08%** | **0.14%** | **100.00%** *(see note below)* |
| **F1-Score** | 0.0104 | 0.2601 | 0.9953 |
| **Accuracy** | 50.30% | 57.48% | 99.07% |

> [!NOTE]
> **Mathematical Interpretation of Policy C Specificity (0.0%):**
> In Policy C, all 4,993 clean Tranco domains that produced zero heuristic findings abstained (`classification=None`) and were excluded from the conclusive subset. The only 7 legitimate samples that entered Policy C were those that triggered heuristic anomalies (the 7 false positives). Thus, $TN = 0$ and $FP = 7$, yielding $\text{Specificity} = \frac{0}{0 + 7} = 0.0\%$ and $\text{FPR} = \frac{7}{7 + 0} = 100.0\%$.
> Reporting 0% specificity is conditional on the conclusive-only subset and does **not** mean the detector flags all benign traffic; as demonstrated under Policy B, the detector correctly declined to warn on 99.86% of the benign reference baseline. Policy C must always be reported alongside the 7.54% coverage metric.
