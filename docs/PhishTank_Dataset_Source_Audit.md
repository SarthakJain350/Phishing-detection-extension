# PhishTank Dataset Source Audit

> **Document Version:** 1.0
> **Date:** November 11, 2026
> **Target Dataset Candidate:** PhishTank (Verified Phishing Feed)
> **Operator:** Cisco Talos Intelligence Group (originally OpenDNS)
> **Primary Source Portal:** `https://www.phishtank.com/developer_info.php` / `https://data.phishtank.com/`
> **Mode:** 100% Offline Static Code Inspection & External Web Verification (Zero Downloads Executed)

---

## Executive Summary

| Evaluation Dimension | Status | Key Finding |
| :--- | :--- | :--- |
| **Official Source & Feeds** | **Verified Fact** | Downloadable bulk feeds are officially hosted at `https://data.phishtank.com/data/[<app_key>/]online-valid.<format>`. |
| **Supported Formats** | **Verified Fact** | CSV, JSON, XML, Serialized PHP (available uncompressed, `.gz`, and `.bz2`). |
| **Field Schema** | **Verified Fact** | `phish_id`, `url`, `phish_detail_url`, `submission_time`, `verified`, `verification_time`, `online`, `target`. |
| **Verification Mechanism** | **Verified Fact** | Crowdsourced community voting consensus backed by user-reputation weighting and Cisco Talos telemetry. |
| **Update Cadence** | **Verified Fact** | Refreshed globally **hourly on the hour**. |
| **Access & Rate Limits** | **Verified Fact** | Free registration for application key (`app_key`). Unauthenticated downloads are restricted to a few per day and heavily throttled; authenticated requests allow regular automated pulls. Descriptive `User-Agent` is mandatory. |
| **Licence & Permitted Use** | **Verified Fact** | Free for commercial and non-commercial/academic use with required attribution: *"Data provided by PhishTank"*. |
| **Offline Academic Suitability** | **Verified Fact** | Highly suitable for offline deterministic evaluation when frozen as a dated, version-controlled benchmark snapshot. |
| **Key Risk / Limitation** | **Technical Inference** | Temporal decay (phishing sites expire quickly), reporting bias towards high-profile financial brands, and dynamic nature requiring static freezing. |
| **Final Recommendation** | **Definitive Finding** | **APPROVED AS PRIMARY PHISHING CANDIDATE**: PhishTank `online-valid.csv` (or `.json`) provides high-fidelity, verified phishing URLs with clear provenance and permissive licensing. |

---

## 1. Official Source & Access Method

### 1.1 Provider & Portal
PhishTank is an open community-clearinghouse for phishing data operated by **Cisco Talos Intelligence Group** (acquired through OpenDNS).

- **Official Web Portal:** `https://www.phishtank.com/`
- **Developer Documentation:** `https://www.phishtank.com/developer_info.php`
- **Bulk Data Host:** `https://data.phishtank.com/data/`
- **Lookup API Host:** `https://checkurl.phishtank.com/checkurl/`

### 1.2 Access Protocol
Bulk files are retrieved via HTTPS GET requests. When using an authorized application key (`app_key`), the key is included in the URL path:
```text
https://data.phishtank.com/data/<app_key>/online-valid.csv.gz
```
Anonymous requests (omitting `<app_key>/`) default to:
```text
https://data.phishtank.com/data/online-valid.csv
```

---

## 2. Available Feeds & Supported Formats

### 2.1 Feed Categories
PhishTank maintains two primary classes of downloadable databases:
1. **`online-valid` (Recommended Operational Feed):** Contains URLs verified by the community as valid phishing attempts (`verified == "yes"`) and actively verified as online/responding (`online == "yes"`).
2. **`all` (Complete Archive):** Contains all historical submissions, including unverified links, community-rejected submissions ("not a phish"), and offline/retired phishing sites.

### 2.2 Supported File Formats & Compression
The `online-valid` feed is generated in four standard serialization formats, each available uncompressed or compressed with gzip or bzip2:

| Format | Uncompressed Endpoint | Gzip Compressed Endpoint (`.gz`) | Bzip2 Compressed Endpoint (`.bz2`) |
| :--- | :--- | :--- | :--- |
| **CSV** | `.../online-valid.csv` | `.../online-valid.csv.gz` | `.../online-valid.csv.bz2` |
| **JSON** | `.../online-valid.json` | `.../online-valid.json.gz` | `.../online-valid.json.bz2` |
| **XML** | `.../online-valid.xml` | `.../online-valid.xml.gz` | `.../online-valid.xml.bz2` |
| **PHP** | `.../online-valid.php_serialized` | `.../online-valid.php_serialized.gz` | `.../online-valid.php_serialized.bz2` |

---

## 3. Field Descriptions & Schema Compatibility

### 3.1 Official CSV Schema
In `online-valid.csv`, the first row is an explicit header with 8 fields:
```csv
phish_id,url,phish_detail_url,submission_time,verified,verification_time,online,target
```

| Field Name | Type | Description |
| :--- | :--- | :--- |
| **`phish_id`** | Integer / String | Unique tracking ID assigned to the phish in the PhishTank database. |
| **`url`** | String | The exact malicious URL reported and verified. |
| **`phish_detail_url`** | String (URI) | Web link to the PhishTank community verification page for this record. |
| **`submission_time`** | ISO 8601 Timestamp | Timestamp when the submission was originally submitted by a reporter. |
| **`verified`** | String (`yes` / `no`) | In `online-valid`, this is always `"yes"`. |
| **`verification_time`**| ISO 8601 Timestamp | Timestamp when community consensus verified the record as phishing. |
| **`online`** | String (`yes` / `no`) | In `online-valid`, this is always `"yes"`. |
| **`target`** | String | The entity, brand, or institution being impersonated (e.g. *PayPal*, *Microsoft*, *Other*). |

### 3.2 Compatibility with Existing Project Parser
Inspection of `evaluation/prepare_dataset.py` confirms that `parse_phishtank_file()` is already implemented and directly matches this schema:
- Extracts `row.get("url")` for ground-truth URL string.
- Maps `label = "phishing"`.
- Extracts `source_id = str(row.get("phish_id"))`.
- Extracts `collection_date = row.get("submission_time")`.
- Extracts `threat_type = "phishing"`.
- Extracts `notes = row.get("target")`.
- Supports uncompressed `.csv`, `.json`, and compressed `.csv.gz`/`.gz`.

---

## 4. Verification Mechanism

### 4.1 Crowdsourced Community Consensus ("The Tank")
PhishTank operates an open, crowdsourced verification model:
1. **Submission:** Registered community users or automated reporting partners submit suspicious URLs.
2. **Review Queue:** The URL enters "The Tank" queue where registered users review the page, view cached screenshots/headers, and cast votes: *"Is this a phish?"* or *"Not a phish"*.
3. **Consensus Algorithm:** A URL is marked `verified = yes` only after meeting a threshold of positive community votes.
4. **Reputation Weighting:** User votes are weighted based on their historical accuracy track record to mitigate sybil attacks and gaming.
5. **Cisco Talos Oversight:** Cisco Talos provides back-end telemetry and operational integrity oversight to weed out abusive manipulation.

---

## 5. Update Frequency & Cadence

- **Batch Generation:** The bulk files (`online-valid.*`) are rebuilt and published globally **hourly on the hour** (e.g., 01:00 UTC, 02:00 UTC).
- **Feed Retention:** Each hourly export overwrites the active file. Historical hourly snapshots are not hosted permanently on the public server; consumers are expected to store their own historical snapshots.

---

## 6. API, Authentication & Rate-Limit Requirements

### 6.1 Application Key (`app_key`)
- Registration is free via `https://www.phishtank.com/`. Users generate an `app_key` under their developer settings.
- The project already has a check script (`evaluation/_check_key.py`) to verify if `PHISHTANK_API_KEY` is present in local environment without exposing secrets.

### 6.2 Rate Limits & Throttling
- **Without an API key:** Bulk downloads are heavily throttled and restricted to a few downloads per day. Exceeding limits results in HTTP 509 (Bandwidth Limit Exceeded) or HTTP 429/403 blocks.
- **With an API key:** Bulk downloads may be pulled on a scheduled hourly basis without hitting bandwidth caps.
- **Header Tracking:** Responses include `X-Request-Limit-Interval`, `X-Request-Limit`, and `X-Request-Count`.

### 6.3 Mandatory User-Agent Header
PhishTank **strictly mandates** a descriptive `User-Agent` HTTP request header identifying the client (e.g. `User-Agent: phishtank/username` or `User-Agent: PhishingDetectorEvaluation/1.0`). Generic or blank headers (e.g. default `curl` or `python-requests`) trigger automated security blocks.

---

## 7. Licence & Permitted Use Conditions

### 7.1 Commercial and Academic Rights
Based on PhishTank's official Developer Terms and Terms of Use (governed by Cisco / OpenDNS):
- **Data Usage:** The threat data provided via the bulk downloads and API is provided **free of charge** and is explicitly permitted for both **non-commercial/academic research and commercial product integration**.
- **Attribution Requirement:** When using PhishTank data in software, evaluation benchmarks, or academic papers, attribution is required.
  - Standard citation: *"Data provided by PhishTank (https://www.phishtank.com/)"*
- **Warranty Disclaimer:** Data is provided strictly *"as-is"* without warranty. PhishTank accepts no liability for false positives or false negatives resulting from feed consumption.

---

## 8. Suitability for Offline Academic Evaluation

### 8.1 Why PhishTank is Highly Suitable
1. **Pure Phishing Focus:** Unlike mixed threat datasets (e.g., CIC-Trap4Phish or URLhaus), PhishTank explicitly discards malware payloads, port-scan bots, and ordinary spam that lack deceptive impersonation. Every verified URL represents a targeted social engineering phish.
2. **Explicit Ground Truth:** The `verified` status is confirmed through independent consensus rather than noisy automated heuristics.
3. **Structured Attribution:** Fields like `target` identify the impersonated brand (e.g. *Apple*, *PayPal*, *Internal Banking*), allowing fine-grained breakdown of detection heuristics by spoofed entity.
4. **Offline Compatibility:** Downloading a single snapshot (`online-valid.csv.gz`) provides thousands of active URLs that can be evaluated offline using our deterministic heuristics engine without any live network calls.

### 8.2 Reproducibility Protocol
Because PhishTank updates hourly, real-time live polling is non-reproducible. To achieve a valid academic evaluation:
1. Download a single hourly snapshot file (e.g. `phishtank_snapshot_YYYYMMDD_HHMM.csv`).
2. Record the exact snapshot download timestamp and record count.
3. Compute and document the SHA-256 hash of the raw snapshot.
4. Store the snapshot in `data/raw/` (ignored by Git per `.gitignore`).
5. Process and evaluate through `evaluation/prepare_dataset.py` and `evaluation/evaluate.py`.

---

## 9. Limitations, Risks & Unresolved Questions

### 9.1 Known Limitations & Risks
1. **Brand Reporting Bias:** PhishTank relies on user submissions, creating a heavy reporting bias towards globally recognized financial, technology, and social media brands (PayPal, Microsoft, Google, Amazon, Apple, Netflix). Lesser-known localized phish may be underrepresented.
2. **Temporal Decay & Liveness:** Phishing websites have short lifespans (median < 24-48 hours). While `online-valid` targets sites verified as online at publication, URLs expire rapidly. (Note: For our offline deterministic evaluation, this is irrelevant because our engine evaluates URL strings without live HTTP visits).
3. **Phishing-Only Scope:** PhishTank contains zero benign samples. A paired negative baseline (e.g. Tranco Top Sites) is strictly required to evaluate false positives, specificity, and precision.

### 9.2 Unresolved Questions
1. **Exact Verification Latency:** What is the median time elapsed between `submission_time` and `verification_time`? (Can be answered empirically by analyzing the timestamp delta in the downloaded snapshot).
2. **Target Field Completeness:** What proportion of entries list `target = "Other"` or an empty string versus a specific brand name?

---

## 10. Final Recommendation

### **Status: APPROVED AS PRIMARY PHISHING CANDIDATE**

PhishTank `online-valid.csv` (or `.json`) is officially approved as the primary positive-class candidate for Phase 5 offline evaluation:
- Clean, verified phishing ground truth.
- Free and permitted for evaluation and commercial products.
- Schema directly matches our existing `parse_phishtank_file()` adapter.
- Pair with a verified benign source (Tranco) to establish the complete binary benchmark.
