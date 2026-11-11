#!/usr/bin/env python3
"""Phase 5 Dataset Preparation Scaffold for Phishing Attack Detector.

Prepares, normalizes, deduplicates, and formats phishing and legitimate URL
datasets from local raw source files (PhishTank, URLhaus, OpenPhish, Tranco)
into a unified JSONL dataset suitable for offline deterministic evaluation.

SAFETY & METHODOLOGY RULES:
- Zero live network requests or downloads performed by this script.
- Deduplicates URLs by canonical form and preserves ground-truth labels.
- Preserves source provenance, collection timestamps, and threat annotations.
- URLhaus distinction: Explicitly marks threat types because URLhaus contains
  malware distribution and payload URLs, not solely phishing URLs.
- Tranco integration: Formats raw domains into standard HTTPS URLs without
  relying on obsolete or proprietary lists like Alexa Top-1K.
"""

from __future__ import annotations

import argparse
import csv
import gzip
import io
import json
import logging
import sys
import urllib.parse
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Generator, Iterator, List, Optional, Set, Tuple

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("prepare_dataset")


def normalize_url_for_eval(raw_url: str) -> Optional[str]:
    """Normalize a URL string for deduplication and evaluation.

    - Strips whitespace.
    - Validates scheme is HTTP or HTTPS.
    - Strips trailing slashes if path is only root.
    - Rejects invalid or blank URLs.
    """
    cleaned = (raw_url or "").strip()
    if not cleaned:
        return None

    # Default to https:// if raw domain provided (e.g. from Tranco list)
    if "://" not in cleaned:
        cleaned = f"https://{cleaned}"

    try:
        parsed = urllib.parse.urlsplit(cleaned)
    except Exception:
        return None

    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        return None

    netloc = parsed.netloc.lower().rstrip(".")
    if not netloc:
        return None

    path = parsed.path or "/"
    # Clean redundant trailing slashes on bare root
    if path == "":
        path = "/"

    # Reconstruct normalized URL (preserve query and fragment if present)
    normalized = urllib.parse.urlunsplit((scheme, netloc, path, parsed.query, parsed.fragment))
    return normalized


def parse_phishtank_file(path: Path, limit: Optional[int] = None) -> Generator[Dict[str, Any], None, None]:
    """Parse a local PhishTank CSV, CSV.GZ, or JSON dump.

    Attribution requirement: Data provided by PhishTank (Cisco Talos).
    """
    logger.info("Reading PhishTank data from %s", path)
    count = 0
    if path.suffix.lower() == ".json":
        with path.open("r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
            for item in data:
                url = item.get("url")
                if not url:
                    continue
                yield {
                    "url": url,
                    "label": "phishing",
                    "source": "phishtank",
                    "source_id": str(item.get("phish_id", "")),
                    "collection_date": item.get("submission_time", datetime.now(timezone.utc).isoformat()),
                    "threat_type": "phishing",
                    "notes": item.get("target", "unspecified_target"),
                }
                count += 1
                if limit and count >= limit:
                    break
    elif path.name.lower().endswith(".csv.gz") or path.suffix.lower() == ".gz":
        with gzip.open(path, "rt", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                url = row.get("url")
                if not url:
                    continue
                yield {
                    "url": url,
                    "label": "phishing",
                    "source": "phishtank",
                    "source_id": str(row.get("phish_id", "")),
                    "collection_date": row.get("submission_time", datetime.now(timezone.utc).isoformat()),
                    "threat_type": "phishing",
                    "notes": row.get("target", "unspecified_target"),
                }
                count += 1
                if limit and count >= limit:
                    break
    else:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                url = row.get("url")
                if not url:
                    continue
                yield {
                    "url": url,
                    "label": "phishing",
                    "source": "phishtank",
                    "source_id": str(row.get("phish_id", "")),
                    "collection_date": row.get("submission_time", datetime.now(timezone.utc).isoformat()),
                    "threat_type": "phishing",
                    "notes": row.get("target", "unspecified_target"),
                }
                count += 1
                if limit and count >= limit:
                    break


def parse_urlhaus_file(path: Path) -> Generator[Dict[str, Any], None, None]:
    """Parse a local URLhaus CSV dump.

    IMPORTANT: URLhaus is primarily a malware distribution / payload URL feed,
    NOT exclusively a phishing feed. Entries are tagged with threat_type.
    License: CC0 Public Domain (abuse.ch).
    """
    logger.info("Reading URLhaus data from %s", path)
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        # Skip comment lines starting with '#'
        lines = (line for line in f if not line.startswith("#"))
        reader = csv.DictReader(lines)
        for row in reader:
            url = row.get("url")
            if not url:
                continue
            threat = row.get("threat", "malware_download")
            tags = row.get("tags", "")
            # Determine explicit threat type
            is_phish = "phish" in threat.lower() or "phish" in tags.lower()
            yield {
                "url": url,
                "label": "phishing" if is_phish else "malware_url",
                "source": "urlhaus",
                "source_id": str(row.get("id", "")),
                "collection_date": row.get("dateadded", datetime.now(timezone.utc).isoformat()),
                "threat_type": "phishing" if is_phish else threat,
                "notes": f"url_status={row.get('url_status', '')}; tags={tags}",
            }


def parse_openphish_file(path: Path) -> Generator[Dict[str, Any], None, None]:
    """Parse a local OpenPhish TXT or JSON feed.

    Terms: Non-commercial evaluation use; attribution required.
    """
    logger.info("Reading OpenPhish data from %s", path)
    now_iso = datetime.now(timezone.utc).isoformat()
    if path.suffix.lower() == ".json":
        with path.open("r", encoding="utf-8", errors="replace") as f:
            data = json.load(f)
            for item in data:
                url = item.get("url") if isinstance(item, dict) else str(item)
                if not url:
                    continue
                yield {
                    "url": url,
                    "label": "phishing",
                    "source": "openphish",
                    "source_id": "",
                    "collection_date": now_iso,
                    "threat_type": "phishing",
                    "notes": "openphish_feed",
                }
    else:
        with path.open("r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                yield {
                    "url": line,
                    "label": "phishing",
                    "source": "openphish",
                    "source_id": "",
                    "collection_date": now_iso,
                    "threat_type": "phishing",
                    "notes": "openphish_feed",
                }


def parse_tranco_file(path: Path, limit: Optional[int] = None) -> Generator[Dict[str, Any], None, None]:
    """Parse a local Tranco top sites CSV list (rank,domain) or CSV.ZIP.

    License: CC-BY-4.0 (Pochat et al.).
    Constructs legitimate HTTPS targets from ranked top domains.
    """
    logger.info("Reading Tranco top sites list from %s", path)
    now_iso = datetime.now(timezone.utc).isoformat()
    count = 0

    if path.suffix.lower() == ".zip":
        with zipfile.ZipFile(path) as z:
            csv_name = [n for n in z.namelist() if n.endswith(".csv")][0]
            with z.open(csv_name) as zf:
                reader = csv.reader(io.TextIOWrapper(zf, encoding="utf-8", errors="replace"))
                for row in reader:
                    if not row or len(row) < 2:
                        continue
                    rank, domain = row[0].strip(), row[1].strip()
                    if not domain:
                        continue
                    url = f"https://{domain}/"
                    yield {
                        "url": url,
                        "label": "legitimate",
                        "source": "tranco",
                        "source_id": rank,
                        "collection_date": now_iso,
                        "threat_type": "benign",
                        "notes": f"tranco_rank={rank}",
                    }
                    count += 1
                    if limit and count >= limit:
                        break
    else:
        with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
            reader = csv.reader(f)
            for row in reader:
                if not row or len(row) < 2:
                    continue
                rank, domain = row[0].strip(), row[1].strip()
                if not domain:
                    continue
                url = f"https://{domain}/"
                yield {
                    "url": url,
                    "label": "legitimate",
                    "source": "tranco",
                    "source_id": rank,
                    "collection_date": now_iso,
                    "threat_type": "benign",
                    "notes": f"tranco_rank={rank}",
                }
                count += 1
                if limit and count >= limit:
                    break


def parse_cic_trap4phish_file(path: Path, limit: Optional[int] = None) -> Generator[Dict[str, Any], None, None]:
    """Parse the CIC‑Trap4Phish 2025 CSV file.

    Expected columns:
      - url: raw URL string (may lack scheme)
      - label: integer 0 (benign) or 1 (phishing)

    Yields dictionaries compatible with the evaluation pipeline.
    """
    # Enforce limit semantics: None = unlimited, positive int = max rows, zero/negative -> error
    if limit is not None and limit <= 0:
        raise ValueError("limit must be a positive integer or None")
    logger.info("Reading CIC‑Trap4Phish data from %s", path)
    count = 0
    with path.open("r", encoding="utf-8", errors="replace", newline="") as f:
        reader = csv.DictReader(f)
        for idx, row in enumerate(reader, start=1):
            raw_url = row.get("url")
            raw_label = row.get("label")
            if not raw_url or raw_label is None:
                continue
            try:
                label_int = int(raw_label)
            except ValueError:
                continue
            if label_int not in (0, 1):
                continue
            label_str = "phishing" if label_int == 1 else "legitimate"
            # Validate and normalize URL
            norm = normalize_url_for_eval(raw_url)
            if not norm:
                continue
            # Additional sanity: validate hostname
            parsed = urllib.parse.urlsplit(norm)
            if not parsed.hostname:
                continue
            if "." not in parsed.hostname:
                continue
            # Reject hostnames with consecutive dots (e.g., a..b)
            if ".." in parsed.hostname:
                continue
            yield {
                "url": raw_url,
                "label": label_str,
                "source": "cic_trap4phish",
                "source_id": str(idx),
                "collection_date": "unknown",
                "threat_type": label_str,
                "notes": "CIC‑Trap4Phish 2025",
            }
            count += 1
            if limit is not None and count >= limit:
                break

def get_synthetic_smoke_samples() -> List[Dict[str, Any]]:
    """Return a fixed set of synthetic samples for offline smoke testing.

    Includes clear structural phishing samples, brand-spoofing samples,
    and standard benign samples without making network calls.
    """
    now_iso = "2026-11-10T00:00:00Z"
    return [
        # Phishing cases targeting structural heuristics
        {
            "url": "http://192.168.1.100/login/paypal/verify.html",
            "label": "phishing",
            "source": "synthetic_smoke_test",
            "source_id": "smoke-phish-1",
            "collection_date": now_iso,
            "threat_type": "phishing",
            "notes": "IP address hostname with brand in path",
        },
        {
            "url": "https://paypal.com.account-update.security-check.xyz/login",
            "label": "phishing",
            "source": "synthetic_smoke_test",
            "source_id": "smoke-phish-2",
            "collection_date": now_iso,
            "threat_type": "phishing",
            "notes": "Misleading subdomain with brand prefix and deep nesting",
        },
        {
            "url": "https://xn--pypal-4ve.com/account/signin",
            "label": "phishing",
            "source": "synthetic_smoke_test",
            "source_id": "smoke-phish-3",
            "collection_date": now_iso,
            "threat_type": "phishing",
            "notes": "Punycode lookalike homoglyph domain",
        },
        {
            "url": "https://user:password@secure-login.suspicious-portal.org/auth",
            "label": "phishing",
            "source": "synthetic_smoke_test",
            "source_id": "smoke-phish-4",
            "collection_date": now_iso,
            "threat_type": "phishing",
            "notes": "@ symbol in URL authority / redirect obfuscation",
        },
        {
            "url": "https://verify-apple-id-credential-reset-urgent-action-required-now.example-phish.net/step1",
            "label": "phishing",
            "source": "synthetic_smoke_test",
            "source_id": "smoke-phish-5",
            "collection_date": now_iso,
            "threat_type": "phishing",
            "notes": "Excessive hyphens and long domain targeting credential reset",
        },
        # Legitimate cases from known clean domains
        {
            "url": "https://www.google.com/",
            "label": "legitimate",
            "source": "synthetic_smoke_test",
            "source_id": "smoke-legit-1",
            "collection_date": now_iso,
            "threat_type": "benign",
            "notes": "Standard benign high-traffic domain",
        },
        {
            "url": "https://github.com/about",
            "label": "legitimate",
            "source": "synthetic_smoke_test",
            "source_id": "smoke-legit-2",
            "collection_date": now_iso,
            "threat_type": "benign",
            "notes": "Standard benign service URL",
        },
        {
            "url": "https://en.wikipedia.org/wiki/Phishing",
            "label": "legitimate",
            "source": "synthetic_smoke_test",
            "source_id": "smoke-legit-3",
            "collection_date": now_iso,
            "threat_type": "benign",
            "notes": "Informational page on legitimate domain",
        },
        {
            "url": "https://www.apple.com/iphone/",
            "label": "legitimate",
            "source": "synthetic_smoke_test",
            "source_id": "smoke-legit-4",
            "collection_date": now_iso,
            "threat_type": "benign",
            "notes": "Genuine brand website",
        },
        {
            "url": "https://docs.python.org/3/library/urllib.parse.html",
            "label": "legitimate",
            "source": "synthetic_smoke_test",
            "source_id": "smoke-legit-5",
            "collection_date": now_iso,
            "threat_type": "benign",
            "notes": "Standard developer documentation URL",
        },
    ]


def build_dataset(
    phishtank_file: Optional[Path] = None,
    phishtank_limit: Optional[int] = None,
    urlhaus_file: Optional[Path] = None,
    openphish_file: Optional[Path] = None,
    tranco_file: Optional[Path] = None,
    tranco_limit: Optional[int] = None,
    smoke_test: bool = False,
    cic_trap4phish_file: Optional[Path] = None,
    cic_trap4phish_limit: Optional[int] = None,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    """Assemble and deduplicate evaluation samples."""
    raw_samples: List[Dict[str, Any]] = []

    if smoke_test:
        logger.info("Using built-in synthetic smoke test samples.")
        raw_samples.extend(get_synthetic_smoke_samples())

    if phishtank_file and phishtank_file.exists():
        raw_samples.extend(parse_phishtank_file(phishtank_file, limit=phishtank_limit))

    if urlhaus_file and urlhaus_file.exists():
        raw_samples.extend(parse_urlhaus_file(urlhaus_file))

    if openphish_file and openphish_file.exists():
        raw_samples.extend(parse_openphish_file(openphish_file))

    if tranco_file and tranco_file.exists():
        raw_samples.extend(parse_tranco_file(tranco_file, limit=tranco_limit))

    # CIC‑Trap4Phish dataset support
    if cic_trap4phish_file and cic_trap4phish_file.exists():
        raw_samples.extend(parse_cic_trap4phish_file(cic_trap4phish_file, limit=cic_trap4phish_limit))


    # Deduplicate while preserving provenance
    seen_urls: Set[str] = set()
    deduped_samples: List[Dict[str, Any]] = []
    duplicate_count = 0
    conflict_count = 0
    source_counts: Dict[str, int] = {}
    label_counts: Dict[str, int] = {}

    for sample in raw_samples:
        norm_url = normalize_url_for_eval(sample["url"])
        if not norm_url:
            continue

        sample["normalized_url"] = norm_url

        if norm_url in seen_urls:
            duplicate_count += 1
            continue

        seen_urls.add(norm_url)
        deduped_samples.append(sample)

        src = sample.get("source", "unknown")
        lbl = sample.get("label", "unknown")
        source_counts[src] = source_counts.get(src, 0) + 1
        label_counts[lbl] = label_counts.get(lbl, 0) + 1

    stats = {
        "raw_total": len(raw_samples),
        "deduped_total": len(deduped_samples),
        "duplicate_count": duplicate_count,
        "source_counts": source_counts,
        "label_counts": label_counts,
    }

    return deduped_samples, stats


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phase 5 Dataset Preparation Scaffold for Phishing Attack Detector",
    )
    parser.add_argument("--phishtank-file", type=Path, help="Path to local PhishTank CSV/JSON file")
    parser.add_argument("--phishtank-limit", type=int, default=None, help="Max entries to take from PhishTank")
    parser.add_argument("--urlhaus-file", type=Path, help="Path to local URLhaus CSV file")
    parser.add_argument("--openphish-file", type=Path, help="Path to local OpenPhish TXT/JSON file")
    parser.add_argument("--tranco-file", type=Path, help="Path to local Tranco CSV list")
    parser.add_argument("--tranco-limit", type=int, default=5000, help="Max entries to take from Tranco list")
    parser.add_argument("--smoke-test", action="store_true", help="Generate synthetic smoke test dataset")
    parser.add_argument("--output", type=Path, default=Path("evaluation/dataset.jsonl"), help="Output JSONL path")

    args = parser.parse_args()

    if not any([args.phishtank_file, args.urlhaus_file, args.openphish_file, args.tranco_file, args.smoke_test]):
        logger.warning("No input sources specified. Defaulting to --smoke-test.")
        args.smoke_test = True

    samples, stats = build_dataset(
        phishtank_file=args.phishtank_file,
        phishtank_limit=args.phishtank_limit,
        urlhaus_file=args.urlhaus_file,
        openphish_file=args.openphish_file,
        tranco_file=args.tranco_file,
        tranco_limit=args.tranco_limit,
        smoke_test=args.smoke_test,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8") as f:
        for s in samples:
            f.write(json.dumps(s) + "\n")

    logger.info("Saved %d samples to %s", len(samples), args.output)
    logger.info("Dataset Stats: %s", json.dumps(stats, indent=2))


if __name__ == "__main__":
    main()
