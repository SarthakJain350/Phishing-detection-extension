#!/usr/bin/env python3
"""Phase 5 Offline Deterministic Evaluation Runner for Phishing Attack Detector.

Runs offline dataset evaluation across pre-collected URL datasets using only
deterministic heuristics and the core detection orchestrator.

STRICT CONSTRAINTS COMPLIANCE:
- 100% offline: zero live network requests, page fetching, or domain resolutions.
- Zero Gemini API calls (opt_in_gemini=False; no API token used or exposed).
- Zero live reputation calls (reputation=None; no Safe Browsing lookups).
- Zero changes to existing production detection logic, schemas, or scoring thresholds.
- Explicit label handling: labels are ground truth ('phishing' vs 'legitimate').
- Transparent inconclusive handling: results with classification=None are NEVER
  silently mapped to phishing. They are reported separately alongside coverage metrics.
- Multi-policy binary mapping: avoids arbitrary assumptions (e.g., risk_score >= 40)
  by reporting both raw classifications and explicit, documented policy mappings.
"""

from __future__ import annotations

import argparse
import json
import logging
import math
import sys
import time
import urllib.parse
from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Ensure repository root is on sys.path for backend imports
REPO_ROOT = Path(__file__).resolve().parent.parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from backend.app.core.domain import extract_domain_info
from backend.app.detection.heuristics import DeterministicHeuristicsEngine
from backend.app.detection.orchestrator import DetectionResult, RealDetectionOrchestrator

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger("evaluate")


def redact_url_for_display(url: str) -> str:
    """Redact sensitive query parameters, credentials, and deep paths for reporting."""
    try:
        parsed = urllib.parse.urlsplit(url)
        host = parsed.hostname or parsed.netloc
        scheme = parsed.scheme or "https"
        path = parsed.path
        if len(path) > 25:
            path = path[:15] + "...[redacted]"
        query_part = "?[redacted_query]" if parsed.query else ""
        return f"{scheme}://{host}{path}{query_part}"
    except Exception:
        return "[redacted_url]"


@dataclass
class EvaluationRecord:
    url: str
    ground_truth: str
    source: str
    collection_date: str
    threat_type: str
    classification: Optional[str]
    risk_score: Optional[int]
    analysis_status: str
    evidence_rules: List[str]
    reasons: List[str]
    heuristics_status: str
    is_conclusive: bool
    source_id: str = ""


@dataclass
class BinaryMetrics:
    total: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    specificity: float
    false_positive_rate: float
    f1_score: float
    accuracy: float


def compute_binary_metrics(
    records: List[EvaluationRecord],
    positive_predicate,
    target_ground_truth: Set[str] = {"phishing", "malware_url"},
    benign_ground_truth: Set[str] = {"legitimate", "benign"},
) -> BinaryMetrics:
    """Compute binary classification metrics according to a given positive predicate."""
    tp = fp = tn = fn = 0

    for r in records:
        is_actual_positive = r.ground_truth in target_ground_truth
        is_actual_negative = r.ground_truth in benign_ground_truth

        if not (is_actual_positive or is_actual_negative):
            continue

        predicted_positive = bool(positive_predicate(r))

        if is_actual_positive and predicted_positive:
            tp += 1
        elif is_actual_negative and predicted_positive:
            fp += 1
        elif is_actual_negative and not predicted_positive:
            tn += 1
        elif is_actual_positive and not predicted_positive:
            fn += 1

    total = tp + fp + tn + fn
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    specificity = tn / (tn + fp) if (tn + fp) > 0 else 0.0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0.0
    f1 = 2 * precision * recall / (precision + recall) if (precision + recall) > 0 else 0.0
    accuracy = (tp + tn) / total if total > 0 else 0.0

    return BinaryMetrics(
        total=total,
        true_positives=tp,
        false_positives=fp,
        true_negatives=tn,
        false_negatives=fn,
        precision=precision,
        recall=recall,
        specificity=specificity,
        false_positive_rate=fpr,
        f1_score=f1,
        accuracy=accuracy,
    )


class OfflineGeminiGuard:
    """Safety guard ensuring Gemini cannot be invoked under any circumstance."""

    def analyze_target(self, *args, **kwargs):
        raise RuntimeError("External Gemini analysis is strictly prohibited in offline evaluation mode.")


class OfflineDatasetEvaluator:
    """Evaluates URL datasets offline using DeterministicHeuristicsEngine and RealDetectionOrchestrator."""

    def __init__(self) -> None:
        self.heuristics_engine = DeterministicHeuristicsEngine()
        # Strictly offline: dummy guard for Gemini, None for reputation
        self.orchestrator = RealDetectionOrchestrator(
            heuristics=self.heuristics_engine,
            gemini=OfflineGeminiGuard(),
            reputation=None,
        )

    def evaluate_url(self, url: str) -> DetectionResult:
        """Run a single URL through the offline detection pipeline."""
        domain_info = extract_domain_info(url)
        target_reference = domain_info.target_reference or url

        # Strictly opt-out of external AI analysis (offline mode)
        return self.orchestrator.analyze_website(
            url=url,
            target_reference=target_reference,
            page_title=None,
            visible_text=None,
            opt_in_gemini=False,
        )

    def run(self, samples: List[Dict[str, Any]]) -> List[EvaluationRecord]:
        """Evaluate a batch of dataset samples."""
        records: List[EvaluationRecord] = []
        start_time = time.monotonic()

        for idx, sample in enumerate(samples, 1):
            url = sample["url"]
            ground_truth = sample.get("label", "unknown")
            source = sample.get("source", "unknown")
            source_id = str(sample.get("source_id", ""))
            collection_date = sample.get("collection_date", "unknown")
            threat_type = sample.get("threat_type", ground_truth)

            result = self.evaluate_url(url)

            evidence_rules = [item.type for item in result.evidence]
            is_conclusive = result.classification is not None

            record = EvaluationRecord(
                url=url,
                ground_truth=ground_truth,
                source=source,
                collection_date=collection_date,
                threat_type=threat_type,
                classification=result.classification,
                risk_score=result.risk_score,
                analysis_status=result.analysis_status,
                evidence_rules=evidence_rules,
                reasons=result.reasons,
                heuristics_status=result.tool_statuses.heuristics.status,
                is_conclusive=is_conclusive,
                source_id=source_id,
            )
            records.append(record)

        elapsed = time.monotonic() - start_time
        logger.info("Evaluated %d samples in %.2fs (%.1f items/s)", len(records), elapsed, len(records) / max(elapsed, 0.001))
        return records


def print_evaluation_report(records: List[EvaluationRecord]) -> Dict[str, Any]:
    """Generate and display comprehensive evaluation statistics."""
    total = len(records)
    if total == 0:
        print("\nNo records to report.")
        return {}

    # 1. Ground truth distribution
    gt_counts = Counter(r.ground_truth for r in records)
    source_counts = Counter(r.source for r in records)

    # 2. Conclusive vs Inconclusive coverage
    conclusive_records = [r for r in records if r.is_conclusive]
    inconclusive_records = [r for r in records if not r.is_conclusive]
    coverage_rate = (len(conclusive_records) / total) * 100.0 if total > 0 else 0.0

    # 3. Status distribution
    status_counts = Counter(r.analysis_status for r in records)

    # 4. Classification matrix: Ground Truth vs Classifier Outcome
    # Tracks count of: phishing, suspicious, likely_legitimate, and inconclusive (None)
    matrix: Dict[str, Counter] = defaultdict(Counter)
    for r in records:
        outcome = r.classification if r.classification is not None else "inconclusive (None)"
        matrix[r.ground_truth][outcome] += 1

    # 5. Rule trigger frequency
    rule_counts = Counter(rule for r in records for rule in r.evidence_rules)

    # 6. Binary Evaluation Policies
    # Policy A: High-Confidence Phishing Alert (classification == 'phishing')
    policy_a_metrics = compute_binary_metrics(
        records,
        positive_predicate=lambda r: r.classification == "phishing",
    )

    # Policy B: Actionable Threat Warning (classification in ('phishing', 'suspicious'))
    policy_b_metrics = compute_binary_metrics(
        records,
        positive_predicate=lambda r: r.classification in ("phishing", "suspicious"),
    )

    # Policy C: Conclusive-Only Subset (evaluates only where a classification exists)
    policy_c_metrics = compute_binary_metrics(
        conclusive_records,
        positive_predicate=lambda r: r.classification in ("phishing", "suspicious"),
    )

    # Render formatted CLI output
    separator = "=" * 78
    subsep = "-" * 78

    print(f"\n{separator}")
    print("PHASE 5 DATASET EVALUATION REPORT (OFFLINE DETERMINISTIC)")
    print(separator)
    print(f"Total Evaluated Samples:     {total}")
    print(f"Conclusive Evaluations:       {len(conclusive_records)} ({coverage_rate:.2f}% coverage)")
    print(f"Inconclusive Evaluations:     {len(inconclusive_records)} ({(100.0 - coverage_rate):.2f}% partial/inconclusive)")
    print(f"Data Sources:                {dict(source_counts)}")
    print(f"Ground Truth Distribution:   {dict(gt_counts)}")
    print(f"Analysis Status Breakdown:   {dict(status_counts)}")

    print(f"\n{subsep}")
    print("DETECTOR CLASSIFICATION BREAKDOWN BY GROUND TRUTH")
    print(subsep)
    header = f"{'Ground Truth':<18} | {'Phishing':<10} | {'Suspicious':<12} | {'Likely Legit':<14} | {'Inconclusive':<14} | {'Total':<8}"
    print(header)
    print("-" * len(header))
    for gt in sorted(matrix.keys()):
        row = matrix[gt]
        phish_cnt = row["phishing"]
        susp_cnt = row["suspicious"]
        legit_cnt = row["likely_legitimate"]
        inconcl_cnt = row["inconclusive (None)"]
        gt_tot = sum(row.values())
        print(f"{gt:<18} | {phish_cnt:<10} | {susp_cnt:<12} | {legit_cnt:<14} | {inconcl_cnt:<14} | {gt_tot:<8}")

    print(f"\n{subsep}")
    print("DOCUMENTED BINARY PERFORMANCE POLICIES")
    print(subsep)

    def print_policy(name: str, desc: str, m: BinaryMetrics, extra_note: str = ""):
        print(f"[{name}] {desc}")
        if extra_note:
            print(f"  Note: {extra_note}")
        print(f"  Evaluated N:    {m.total:<6} | Accuracy:    {m.accuracy * 100:.2f}%")
        print(f"  TP: {m.true_positives:<6} FP: {m.false_positives:<6} | Precision:   {m.precision * 100:.2f}%")
        print(f"  FN: {m.false_negatives:<6} TN: {m.true_negatives:<6} | Recall:      {m.recall * 100:.2f}%")
        print(f"  Specificity:    {m.specificity * 100:.2f}% | FPR:         {m.false_positive_rate * 100:.2f}%")
        print(f"  F1-Score:       {m.f1_score:.4f}\n")

    print_policy(
        name="Policy A — High-Confidence Phishing Alert",
        desc="Positive = 'phishing' verdict (risk_score >= 70). Negative = 'suspicious', 'likely_legitimate', or inconclusive.",
        m=policy_a_metrics,
        extra_note="Reflects high-precision blocking threshold without triggering warnings on moderate anomalies.",
    )

    print_policy(
        name="Policy B — Actionable Threat Warning (Sensitive)",
        desc="Positive = 'phishing' OR 'suspicious'. Negative = 'likely_legitimate' or inconclusive.",
        m=policy_b_metrics,
        extra_note="Reflects user-facing warning trigger. Inconclusive outcomes are conservatively treated as negative.",
    )

    print_policy(
        name="Policy C — Conclusive-Only Subset (Conditional on Heuristics)",
        desc="Positive = 'phishing' OR 'suspicious'. Negative = 'likely_legitimate'. Inconclusive outcomes excluded.",
        m=policy_c_metrics,
        extra_note=f"Measures heuristic discrimination conditioned on triggering. Dataset Coverage: {coverage_rate:.2f}%.",
    )

    print(f"{subsep}")
    print("HEURISTIC RULE ACTIVATION FREQUENCY")
    print(subsep)
    if rule_counts:
        for rule, count in rule_counts.most_common():
            pct = (count / total) * 100.0
            print(f"  - {rule:<32}: {count:>5} hits ({pct:>5.1f}%)")
    else:
        print("  (Zero heuristic rules activated across dataset)")

    # False Positive and False Negative Inspection (Policy B: Threat Warning)
    fps_policy_b = [
        r for r in records
        if r.ground_truth in ("legitimate", "benign") and r.classification in ("phishing", "suspicious")
    ]
    fns_policy_b = [
        r for r in records
        if r.ground_truth in ("phishing", "malware_url") and r.classification not in ("phishing", "suspicious")
    ]

    print(f"\n{subsep}")
    print(f"FALSE POSITIVES (Policy B: Benign Flagged as Threat) — Total: {len(fps_policy_b)}")
    print(subsep)
    if fps_policy_b:
        for fp in fps_policy_b[:15]:
            redacted = redact_url_for_display(fp.url)
            print(f"  • ID: {fp.source_id or 'N/A'} | Source: {fp.source} | Classification: {fp.classification} (score: {fp.risk_score})")
            print(f"    URL: {redacted}")
            print(f"    Triggered Rules: {fp.evidence_rules}")
        if len(fps_policy_b) > 15:
            print(f"    ... and {len(fps_policy_b) - 15} more false positives.")
    else:
        print("  None. Zero false positives observed under Policy B.")

    print(f"\n{subsep}")
    print(f"FALSE NEGATIVES (Policy B: Phishing Not Flagged as Threat) — Total: {len(fns_policy_b)}")
    print(subsep)
    if fns_policy_b:
        for fn in fns_policy_b[:15]:
            redacted = redact_url_for_display(fn.url)
            print(f"  • ID: {fn.source_id or 'N/A'} | Source: {fn.source} | Outcome: {fn.classification or 'inconclusive (None)'}")
            print(f"    URL: {redacted}")
            print(f"    Status: {fn.analysis_status} | Reason: {fn.reasons[0] if fn.reasons else 'None'}")
        if len(fns_policy_b) > 15:
            print(f"    ... and {len(fns_policy_b) - 15} more false negatives.")
    else:
        print("  None. All phishing samples were successfully detected under Policy B.")
    print(separator + "\n")

    report_dict = {
        "total_samples": total,
        "conclusive_count": len(conclusive_records),
        "inconclusive_count": len(inconclusive_records),
        "coverage_rate": coverage_rate,
        "ground_truth_distribution": dict(gt_counts),
        "source_distribution": dict(source_counts),
        "status_distribution": dict(status_counts),
        "classification_matrix": {k: dict(v) for k, v in matrix.items()},
        "heuristic_rule_activations": dict(rule_counts),
        "policies": {
            "policy_a_high_confidence": asdict(policy_a_metrics),
            "policy_b_actionable_threat": asdict(policy_b_metrics),
            "policy_c_conclusive_only": asdict(policy_c_metrics),
        },
    }
    return report_dict


def load_dataset(dataset_path: Path) -> List[Dict[str, Any]]:
    """Load JSONL dataset."""
    samples: List[Dict[str, Any]] = []
    with dataset_path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            samples.append(json.loads(line))
    return samples


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Phase 5 Offline Deterministic Evaluation Runner for Phishing Attack Detector",
    )
    parser.add_argument("--dataset", type=Path, help="Path to evaluation JSONL dataset")
    parser.add_argument("--smoke-test", action="store_true", help="Run offline synthetic smoke test")
    parser.add_argument("--output-json", type=Path, help="Optional path to save full JSON report")
    parser.add_argument("--verbose", action="store_true", help="Log details for each evaluated sample")

    args = parser.parse_args()

    if not args.dataset and not args.smoke_test:
        logger.info("Neither --dataset nor --smoke-test specified. Running synthetic smoke test.")
        args.smoke_test = True

    if args.smoke_test:
        from evaluation.prepare_dataset import get_synthetic_smoke_samples
        samples = get_synthetic_smoke_samples()
        logger.info("Loaded %d synthetic smoke test samples.", len(samples))
    else:
        assert args.dataset is not None
        if not args.dataset.exists():
            logger.error("Dataset file not found: %s", args.dataset)
            sys.exit(1)
        samples = load_dataset(args.dataset)
        logger.info("Loaded %d samples from %s", len(samples), args.dataset)

    evaluator = OfflineDatasetEvaluator()
    records = evaluator.run(samples)

    if args.verbose:
        for r in records:
            print(f"[{r.ground_truth.upper()}] URL: {r.url}")
            print(f"  Classification: {r.classification} | Score: {r.risk_score} | Status: {r.analysis_status}")
            print(f"  Rules: {r.evidence_rules}")
            print()

    report = print_evaluation_report(records)

    if args.output_json:
        args.output_json.parent.mkdir(parents=True, exist_ok=True)
        with args.output_json.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        logger.info("Saved report JSON to %s", args.output_json)


if __name__ == "__main__":
    main()
