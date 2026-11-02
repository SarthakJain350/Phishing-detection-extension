/**
 * Status and reason formatting helpers for scan result display.
 * Distinguishes planned unintegrated checks from actual runtime failures (timeouts, errors).
 */

import type { ToolStatusDetail, ToolStatuses, ToolStatusValue } from "./types";

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
 * Checks if any tool suffered an actual runtime failure (timeout, 5xx, transport error).
 */
export function hasRuntimeCheckFailure(toolStatuses?: ToolStatuses): boolean {
  if (!toolStatuses) return false;
  const tools = [toolStatuses.heuristics, toolStatuses.reputation, toolStatuses.llm];
  return tools.some(
    (t) =>
      t.status === "timeout" ||
      t.status === "error" ||
      (t.status === "unavailable" && t.reason_code !== "provider_not_integrated")
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
 * Generates an accurate summary message for partial analysis states.
 * - When a provider is merely not integrated: clarifies advisory nature without sounding like a crash.
 * - When an actual runtime failure or timeout occurred: accurately indicates the failure.
 * - In all cases: reinforces that partial results do not guarantee safety.
 */
export function getPartialAnalysisSummary(
  reasons: string[],
  toolStatuses?: ToolStatuses
): string {
  const reasonSuffix = reasons[0] ? ` ${reasons[0]}` : "";
  if (hasRuntimeCheckFailure(toolStatuses)) {
    return `Some checks could not finish due to a service timeout or error. Treat this result with caution.${reasonSuffix}`;
  }
  if (hasUnintegratedProvider(toolStatuses)) {
    return `Reputation checking is not yet integrated. Results are advisory and do not guarantee safety.${reasonSuffix}`;
  }
  return `Some checks could not finish. Treat this result with caution.${reasonSuffix}`;
}
