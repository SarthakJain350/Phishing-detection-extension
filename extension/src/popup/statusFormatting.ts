/**
 * Status and reason formatting helpers for scan result display.
 * Distinguishes planned unintegrated checks from actual runtime failures (timeouts, errors).
 */

import type { Classification, EvidenceItem, ToolStatusDetail, ToolStatuses, ToolStatusValue } from "./types";

/**
 * Returns human-readable label for a tool status.
 * Distinguishes 'provider_not_integrated' from generic 'unavailable'.
 */
export function getToolStatusLabel(detail: ToolStatusDetail): string {
  if (detail.reason_code === "provider_not_integrated") {
    return "Not integrated";
  }
  const map: Record<ToolStatusValue, string> = {
    complete: "Complete",
    partial: "Partial",
    unavailable: "Unavailable",
    timeout: "Timed out",
    error: "Error",
  };
  return map[detail.status] ?? detail.status;
}

/**
 * Returns true if a tool status represents an actual runtime failure that was
 * not anticipated by design — i.e. a network timeout, a 5xx service error, or
 * an unexpected unavailability that is NOT one of the two planned "not-yet-
 * integrated" states:
 *   - provider_not_integrated  (reputation provider intentionally unintegrated)
 *   - opt_in_required          (Gemini intentionally gated behind user opt-in)
 * Those two states are advisory by design and must not sound like crashes.
 */
export function hasRuntimeCheckFailure(toolStatuses?: ToolStatuses): boolean {
  if (!toolStatuses) return false;
  const tools = [toolStatuses.heuristics, toolStatuses.reputation, toolStatuses.llm];
  const intentionalReasonCodes = new Set(["provider_not_integrated", "opt_in_required"]);
  return tools.some(
    (t) =>
      t.status === "timeout" ||
      t.status === "error" ||
      (t.status === "unavailable" && !intentionalReasonCodes.has(t.reason_code ?? ""))
  );
}

/**
 * Checks if any tool is planned but not yet integrated.
 */
export function hasUnintegratedProvider(toolStatuses?: ToolStatuses): boolean {
  if (!toolStatuses) return false;
  const tools = [toolStatuses.heuristics, toolStatuses.reputation, toolStatuses.llm];
  return tools.some(
    (t) => t.status === "unavailable" && t.reason_code === "provider_not_integrated"
  );
}

/**
 * Returns true when AI content analysis was intentionally skipped because the
 * user has not opted in. This is a planned privacy gate, not a service failure.
 */
export function hasGeminiOptInRequired(toolStatuses?: ToolStatuses): boolean {
  if (!toolStatuses) return false;
  return toolStatuses.llm.status === "unavailable" && toolStatuses.llm.reason_code === "opt_in_required";
}

/**
 * Generates an accurate summary message for partial analysis states.
 * Distinguishes partial-analysis causes:
 *   1. Actual runtime failure (timeout, 5xx, unexpected unavailability) → warns user.
 *   2. Inconclusive assessment (null classification with no runtime failure) → explains that no
 *      suspicious indicators were detected by available checks, but external checks were not performed.
 *   3. Provider not integrated (reputation) → advisory, not a crash.
 *   4. Gemini opt-in disabled → explains that AI analysis was not enabled.
 *   5. Unknown partial state → generic caution.
 * In all cases: reinforces that partial results do not guarantee safety.
 */
export function getPartialAnalysisSummary(
  reasons: string[],
  toolStatuses?: ToolStatuses,
  classification?: Classification,
  targetType: "website" | "email" = "email"
): string {
  const reasonSuffix = reasons[0] ? ` ${reasons[0]}` : "";
  if (hasRuntimeCheckFailure(toolStatuses)) {
    return `Some checks could not finish due to a service timeout or error. Treat this result with caution.${reasonSuffix}`;
  }
  if (classification === null) {
    const targetLabel = targetType === "website" ? "website" : "email";
    return `No suspicious indicators detected by available checks. External AI and reputation checks were not performed. This does not establish that the ${targetLabel} is safe.`;
  }
  if (hasUnintegratedProvider(toolStatuses) && hasGeminiOptInRequired(toolStatuses)) {
    return `Reputation checking is not yet integrated and AI content analysis is disabled (opt-in required). Results are advisory and do not guarantee safety.${reasonSuffix}`;
  }
  if (hasGeminiOptInRequired(toolStatuses)) {
    return `AI content analysis is disabled (opt-in required). Results are advisory and do not guarantee safety.${reasonSuffix}`;
  }
  if (hasUnintegratedProvider(toolStatuses)) {
    return `Reputation checking is not yet integrated. Results are advisory and do not guarantee safety.${reasonSuffix}`;
  }
  return `Some checks could not finish. Treat this result with caution.${reasonSuffix}`;
}

/**
 * Resolves the display configuration for a scan classification.
 * Strictly guarantees that a null classification is NEVER treated or displayed
 * as likely_legitimate or safe, regardless of analysis status.
 */
export type ClassificationVisualKey =
  | "phishing"
  | "suspicious"
  | "likely_legitimate"
  | "unavailable"
  | "partial"
  | "inconclusive";

export interface ClassificationDisplayMeta {
  visualKey: ClassificationVisualKey;
  label: string;
  cssClass: string;
}

export function getClassificationDisplayMeta(
  classification: "phishing" | "suspicious" | "likely_legitimate" | null,
  analysisStatus: "complete" | "partial" | "unavailable",
  targetType: "website" | "email" = "website"
): ClassificationDisplayMeta {
  if (analysisStatus === "unavailable") {
    return {
      visualKey: "unavailable",
      label: "Analysis unavailable",
      cssClass: "classification-badge--unavailable",
    };
  }

  if (analysisStatus === "partial" && classification === null) {
    return {
      visualKey: "partial",
      label: "Partial analysis",
      cssClass: "classification-badge--partial",
    };
  }

  if (classification === null) {
    return {
      visualKey: "inconclusive",
      label: "Analysis inconclusive",
      cssClass: "classification-badge--unavailable",
    };
  }

  if (classification === "phishing") {
    return {
      visualKey: "phishing",
      label: "Phishing risk detected",
      cssClass: "classification-badge--phishing",
    };
  }

  if (classification === "suspicious") {
    return {
      visualKey: "suspicious",
      label: targetType === "email" ? "Suspicious email" : "Suspicious website",
      cssClass: "classification-badge--suspicious",
    };
  }

  return {
    visualKey: "likely_legitimate",
    label: "No strong phishing signals found",
    cssClass: "classification-badge--likely_legitimate",
  };
}

/**
 * Filters scan reasons to produce additional findings, strictly ensuring that:
 * 1. Explanations already displayed in Observed Signals (data.evidence) are excluded.
 * 2. The primary summary reason (data.reasons[0]) is excluded from additional findings
 *    to prevent duplicate display when already presented in the result summary.
 * 3. Identical reason strings are deduplicated.
 */
export function getAdditionalFindings(
  reasons: string[],
  evidence?: EvidenceItem[]
): string[] {
  if (!reasons || reasons.length === 0) return [];
  const evidenceExplanations = new Set(
    (evidence || []).map((item) => item.explanation)
  );
  return Array.from(
    new Set(
      reasons.filter((reason, idx) => {
        if (evidenceExplanations.has(reason)) {
          return false;
        }
        if (idx === 0) {
          return false;
        }
        return true;
      })
    )
  );
}
