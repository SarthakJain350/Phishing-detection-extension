# Tranco Dataset Source Audit

> **Document Version:** 1.0
> **Date:** November 11, 2026
> **Target Dataset Candidate:** Tranco (Top Sites Popularity Ranking)
> **Operator / Maintainers:** Victor Le Pochat et al. (DistriNet Research Group, KU Leuven & Delft University of Technology)
> **Primary Source Portal:** `https://tranco-list.eu/`
> **Reference Paper:** *Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation*, NDSS Symposium 2019
> **Mode:** 100% Offline Static Code Inspection & External Web Verification (Zero Downloads Executed)

---

## Executive Summary

| Evaluation Dimension | Status | Key Finding |
| :--- | :--- | :--- |
| **Official Source & Maintainers** | **Verified Fact** | Maintained by security researchers at KU Leuven and TU Delft; primary portal is `https://tranco-list.eu/`. |
| **Methodology** | **Verified Fact** | Multi-source rank fusion (Borda-like score combination) over a 30-day sliding window, specifically hardened against manipulation. |
| **Underlying Sources** | **Verified Fact** | Combines multiple provider telemetry feeds (Cisco Umbrella, Majestic, Cloudflare Radar, Chrome User Experience Report [CrUX], Farsight; historically included Alexa and Quantcast). |
| **Update Cadence** | **Verified Fact** | Generated daily by 00:00 UTC with an archived unique permanent **List ID**. |
| **Snapshot Selection & Reproducibility** | **Verified Fact** | Highly reproducible via permanent alphanumeric List IDs (e.g., `https://tranco-list.eu/list/<LIST_ID>/`) and immutable daily archives. |
| **Download Formats & Schema** | **Verified Fact** | Zip-compressed CSV (`top-1m.csv.zip`). Format: `rank,domain` (e.g., `1,google.com`). Standard lists provide root second-level domains without header. Full URLs are **not** provided. |
| **Access & Authentication** | **Verified Fact** | Public daily downloads require **no login, no API key, and no registration**. An account is optional only for custom list generation via API. |
| **Licence & Permitted Use** | **Verified Fact** | Composite data subject to source component terms: CC BY 3.0 (Majestic), CC BY-SA 4.0 (CrUX), CC BY-NC 4.0 (Cloudflare Radar), and Umbrella terms. Research use is permitted; commercial redistribution carries NonCommercial and ShareAlike constraints. |
| **Attribution Requirement** | **Verified Fact** | Mandatory citation of the NDSS 2019 research paper (Le Pochat et al.). |
| **Suitability for Academic Evaluation** | **Technical Finding** | **Suitable ONLY as a supplementary benign-domain reference baseline**. Domains are popular, **not guaranteed to be safe**. |
| **Key Risk / Limitation** | **Technical Finding** | Popular domains can host compromised subdomains, malicious paths, or redirectors; lacks full URL paths; requires explicit prefixing (`https://<domain>/`) to conform to URL-based evaluation pipelines. |
| **Final Recommendation** | **Definitive Finding** | **APPROVED AS SUPPLEMENTARY BENIGN REFERENCE BASELINE**: Suitable for evaluating detector false-positive rate and specificity on high-reputation domains, provided the snapshot List ID is recorded and domains are not treated as infallible ground truth. |

---

## 1. Official Source & Maintainers

### 1.1 Academic Provenance
Tranco was developed to address structural flaws in legacy top-site rankings (such as Alexa Top-1M, Cisco Umbrella, and Majestic), specifically excessive daily volatility and vulnerability to low-cost adversary manipulation.

- **Foundational Paper:**
  Victor Le Pochat, Tom Van Goethem, Samaneh Tajalizadehkhoob, Maciej Korczyński, and Wouter Joosen.
  *"Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation"*,
  In *Proceedings of the 26th Annual Network and Distributed System Security Symposium (NDSS 2019)*, San Diego, CA.
  DOI: `10.14722/ndss.2019.23386`
- **Lead Organizations:** DistriNet Research Group (KU Leuven, Belgium) and Delft University of Technology (TU Delft, Netherlands).
- **Official Web Portal:** `https://tranco-list.eu/`
- **Public API Endpoint:** `https://tranco-list.eu/api/`
- **PyPI Client Library:** `tranco` (official Python wrapper)

---

## 2. Ranking Methodology & Underlying Sources

### 2.1 Multi-Source Fusion & Manipulation Hardening
Traditional popularity rankings relied on single telemetry vectors (e.g., Alexa toolbar extensions or Umbrella DNS resolver volume), allowing attackers to artificially inflate the rank of malicious domains with trivial HTTP requests or DNS queries. Tranco mitigates this by:
1. **Multi-Source Combination:** Combining ranking feeds generated through fundamentally different collection methodologies (browser telemetry, global DNS lookups, web-graph crawls). An adversary cannot elevate a domain without compromising all underlying providers simultaneously.
2. **Temporal Smoothing (30-day Window):** Rather than publishing raw daily spikes, Tranco computes a rolling aggregate over the preceding 30 days. This filters transient noise, temporary scanning campaigns, and short-term volatility.
3. **Rank Aggregation Algorithm:** Uses a Borda-count-inspired scoring mechanism with logarithmic diminishing returns across provider lists.

### 2.2 Underlying Ranking Sources
- **Current Active Sources:**
  - **Cisco Umbrella:** Passive DNS (PDNS) traffic from global resolver network.
  - **Majestic:** Web link-graph structure and referring subnets.
  - **Chrome User Experience Report (CrUX):** User-originating navigation telemetry collected via Google Chrome.
  - **Cloudflare Radar:** Global DNS query volume and HTTP traffic metadata observed across Cloudflare's network.
  - **Farsight Security (DomainTools):** Passive DNS telemetry.
- **Historical Sources:** Alexa (discontinued by Amazon in May 2022) and Quantcast (discontinued in 2021).

---

## 3. Update Frequency & Snapshot Reproducibility

### 3.1 Daily Release Schedule
- New default top 1M lists are compiled and released **daily by 00:00 UTC**.

### 3.2 Permanent Snapshot Identification & Reproducibility
A major contribution of the Tranco project is scientific reproducibility:
- Every daily list is assigned a permanent, unique alphanumeric **List ID** (e.g., `66NX`, `N7JW`, `Y83YG`).
- Historical lists are immutable and preserved indefinitely.
- Permanent reference URL format:
  ```text
  https://tranco-list.eu/list/{list_id}/
  ```
- Direct permanent download format:
  ```text
  https://tranco-list.eu/download/{list_id}/1000000
  ```
- Public metadata API for dates:
  ```text
  https://tranco-list.eu/api/lists/date/{YYYY-MM-DD}
  ```
- The identifier of the latest available list can be retrieved dynamically without authentication via:
  ```text
  https://tranco-list.eu/top-1m-id
  ```

---

## 4. Download Formats & Schema

### 4.1 File Format & Delivery
- **Direct Default Endpoint:** `https://tranco-list.eu/top-1m.csv.zip`
- **Compressed Archive:** Standard ZIP containing a single CSV file named `top-1m.csv`.
- **Archive Size:** ~9.5–10 MB compressed (~22–25 MB uncompressed).

### 4.2 Record Structure & Schema
The CSV file contains **no header row**. Each row consists of exactly two comma-separated values:
```text
<rank>,<domain>
```
*Example from actual top entries:*
```csv
1,google.com
2,cloudflare.com
3,ezviz7.com
4,amazonaws.com
5,facebook.com
```

### 4.3 Key Data Structural Characteristics
1. **Domains, Not URLs:** Tranco provides second-level domains (SLDs) or fully qualified hostnames, **never full URL paths or protocols**.
2. **Missing Scheme and Path:** Entries lack `https://` and trailing `/`.
3. **Subdomains:** Standard list aggregates root domains; a separate variant (`top-1m-subdomains.csv.zip`) incorporates fully qualified subdomains.

---

## 5. Compatibility with Existing Project Evaluation Pipeline

### 5.1 Project Adapter Review
Inspection of `evaluation/prepare_dataset.py` lines 213–270 confirms that `parse_tranco_file()` is already implemented to handle Tranco's format:
- Automatically inspects `.zip` archives or raw `.csv` files.
- Reads `row[0]` as `rank` (`source_id`) and `row[1]` as `domain`.
- Synthesizes a valid URL: `url = f"https://{domain}/"`.
- Assigns:
  - `label = "legitimate"`
  - `source = "tranco"`
  - `threat_type = "benign"`
  - `notes = f"tranco_rank={rank}"`
- Supports positive record limits (e.g., `--tranco-limit 5000` to select the top 5,000 domains rather than loading all 1,000,000).

### 5.2 Normalization Alignment
Because Tranco provides raw domain strings (`google.com`), the adapter's construction (`https://google.com/`) cleanly matches `normalize_url_for_eval()`, which enforces lowercase hostnames, validates HTTP/HTTPS schemes, and handles root paths.

---

## 6. Access Requirements & Authentication

- **Public Bulk Downloads:** **100% Free and Unauthenticated.** No API key, token, or account registration is required to download `top-1m.csv.zip` or any historical list by ID.
- **API Custom Lists:** Account creation and an API key are only required if a researcher wishes to generate custom-configured lists (e.g., custom provider weightings or custom exclusion filters).

---

## 7. Licensing & Permitted-Use Conditions

### 7.1 Composite Licensing Complexity
Because Tranco is an aggregation of third-party feeds, its legal terms are composite:
- **Majestic Component:** Creative Commons Attribution (**CC BY 3.0**).
- **Chrome UX Report (CrUX) Component:** Creative Commons Attribution-ShareAlike (**CC BY-SA 4.0**).
- **Cloudflare Radar Component:** Creative Commons Attribution-NonCommercial (**CC BY-NC 4.0**).
- **Cisco Umbrella Component:** Free of charge for research/operational use.

### 7.2 Permitted Use
- **Academic & Research Evaluation:** **Fully Permitted.** The dataset was specifically funded and designed as an open benchmark for cybersecurity research.
- **Commercial Redistribution Restrictions:** Due to the inclusion of Cloudflare Radar (CC BY-NC 4.0) and CrUX (CC BY-SA 4.0) in the default list, commercial vendors cannot freely redistribute the default Tranco list commercially without respecting non-commercial and share-alike constraints.

### 7.3 Mandatory Attribution
Users of Tranco data are required to cite the original NDSS 2019 publication:
```bibtex
@inproceedings{lepochat2019tranco,
  author    = {Le Pochat, Victor and Van Goethem, Tom and Tajalizadehkhoob, Samaneh and Korczy{\'n}ski, Maciej and Joosen, Wouter},
  title     = {Tranco: A Research-Oriented Top Sites Ranking Hardened Against Manipulation},
  booktitle = {Proceedings of the 26th Annual Network and Distributed System Security Symposium (NDSS 2019)},
  year      = {2019},
  doi       = {10.14722/ndss.2019.23386}
}
```

---

## 8. Technical Considerations, Limitations & Risks

### 8.1 Popularity Does Not Equal Innocence
> [!WARNING]
> **Core Limitation:** A top-ranked domain indicates high web traffic or link volume; it **does NOT guarantee the absence of malicious content**.

1. **Compromised Sub-Paths:** High-reputation services frequently host malicious user content. For example, cloud storage providers (`amazonaws.com`, `googleapis.com`, `000webhostapp.com`, `firebaseapp.com`) and code repositories (`github.com`) have top Tranco ranks, but individual tenant paths routinely serve phishing or malware.
2. **Malicious Presence in Top Sites:** The Tranco authors' original NDSS research explicitly documented that **thousands of malicious domains** (2,162 in Majestic alone, and hundreds in Alexa) appeared in top rankings. While Tranco's hardening drastically reduces adversary manipulation, compromised websites (e.g., WordPress sites with high link volume) can still appear in the lower percentiles of the top 1M.
3. **URL-Based Evaluation Mismatch:** Our phishing detector evaluates full URL strings, including query parameters, authority `@` signs, and specific path tokens. Evaluating bare root domains (`https://domain.com/`) tests whether the engine generates false alarms on clean brand names, but does not test detector performance on realistic benign deep URLs (e.g., long e-commerce product paths or news articles).

### 8.2 Reproducibility Protocol for Phase 5
To maintain academic rigor during local evaluation:
1. **Never use an unverified rolling download:** The dynamic link `top-1m.csv.zip` changes daily.
2. **Record the Snapshot List ID:** Inspect and document the exact List ID (e.g., from `https://tranco-list.eu/top-1m-id`) or download a specific historical date.
3. **Document Hash & Metadata:** Record the SHA-256 checksum, snapshot creation date, and row count of the local ZIP file in the evaluation report.
4. **Subsampling Scope:** Use top-ranked domains (e.g., top 1,000–5,000) where the probability of active hosting compromise is lowest.

---

## 9. Distinctions: Facts vs. Observations vs. Inferences

| Dimension | Type | Details |
| :--- | :--- | :--- |
| **Maintainers & NDSS Paper** | **Verified Fact** | Maintained by KU Leuven and TU Delft; peer-reviewed and published at NDSS 2019. |
| **List Format** | **Verified Fact** | Unheaded 2-column CSV (`rank,domain`), zipped, updated daily by 00:00 UTC. |
| **Access Requirements** | **Verified Fact** | Completely free and unauthenticated for bulk downloads. |
| **Local Snapshot Presence** | **Direct Observation** | A snapshot file (`tranco_top_1m.csv.zip`, 9,689,500 bytes) exists locally in `data/raw/`, containing `top-1m.csv` (22,651,820 bytes uncompressed). |
| **Local Snapshot Rank Format** | **Direct Observation** | Rows match expected `rank,domain` structure (`1,google.com`, `2,cloudflare.com`, etc.). |
| **Local Snapshot Provenance** | **Unresolved Question** | The exact download date and permanent List ID for the existing local `data/raw/tranco_top_1m.csv.zip` were not recorded in metadata. |
| **Absence of Malicious Paths** | **Technical Inference** | Evaluating Tranco domains formatted as `https://<domain>/` will test baseline false positives on root domains, but will not represent deep URL topologies. |

---

## 10. Final Recommendation

### **Status: APPROVED AS SUPPLEMENTARY BENIGN REFERENCE BASELINE**

Tranco is officially recommended for the negative (benign) class in Phase 5 offline evaluation, subject to the following operating rules:
1. **Role Definition:** Tranco serves as a **high-reputation benign reference baseline**, primarily to measure false positive rate (FPR) and specificity on popular web properties.
2. **Do Not Treat as Infallible Ground Truth:** Evaluation reports must state that top domains are selected for popularity and stability, not verified by individual human safety audits.
3. **Snapshot Freezing:** When evaluation is executed via PowerShell, the user must record the exact snapshot date, SHA-256 hash, and List ID.
4. **Primary Benchmark Pairing:** Combine **PhishTank** (phishing positive) + **Tranco Top-N** (benign reference) to complete the primary Phase 5 offline evaluation dataset.
