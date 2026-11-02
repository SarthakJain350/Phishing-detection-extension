/**
 * Warning Interstitial Integration for Production Popup
 *
 * Provides:
 * - Policy check for high-risk scan outcomes
 * - Strict URL validation and parameter generation
 * - Tab-shielding navigation trigger
 */

import type { ScanResponse } from "./types";

/**
 * Evaluates whether a scan result constitutes high risk requiring shield actions.
 *
 * Policy:
 * - Failure is never high risk (unavailable returns false).
 * - Explicit classification "phishing" is high risk.
 * - Risk score >= 70 (documented high-risk threshold) is high risk.
 * - Partial results are evaluated conservatively (only if classification or score crosses threshold).
 */
export function isHighRiskScan(data: ScanResponse | null | undefined): boolean {
  if (!data) return false;
  if (data.analysis_status === "unavailable") return false;
  if (data.classification === "phishing") return true;
  if (typeof data.risk_score === "number" && !isNaN(data.risk_score) && data.risk_score >= 70) {
    return true;
  }
  return false;
}

/**
 * Normalizes a hostname string (lowercased, trimmed, trailing dots stripped).
 */
export function normalizeHostname(host: string | null | undefined): string {
  if (!host || typeof host !== "string") return "";
  return host.trim().toLowerCase().replace(/\.+$/, "");
}

export interface WarningUrlOptions {
  destUrl: string;
  riskScore?: number | null;
  reasons?: string[];
  isPartial?: boolean;
}

/**
 * Builds URLSearchParams for the warning page with strict validation and encoding.
 * Throws an Error if destUrl is not a valid HTTP or HTTPS URL.
 */
export function buildWarningUrlParams(options: WarningUrlOptions): URLSearchParams {
  const rawUrl = options.destUrl ? options.destUrl.trim() : "";
  if (!rawUrl) {
    throw new Error("Destination URL must not be empty");
  }

  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error(`Invalid destination URL: '${rawUrl}'`);
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    throw new Error(`Unsupported destination scheme '${parsed.protocol}'. Only http: and https: are permitted.`);
  }

  const hostname = normalizeHostname(parsed.hostname);
  if (!hostname) {
    throw new Error("Destination URL hostname could not be determined");
  }

  const params = new URLSearchParams();
  params.set("domain", hostname);

  if (
    typeof options.riskScore === "number" &&
    !isNaN(options.riskScore) &&
    options.riskScore >= 0 &&
    options.riskScore <= 100
  ) {
    params.set("score", String(Math.round(options.riskScore)));
  }

  params.set("dest", parsed.href);

  if (Array.isArray(options.reasons)) {
    const validReasons = options.reasons
      .map((r) => (typeof r === "string" ? r.trim() : ""))
      .filter((r) => r.length > 0)
      .slice(0, 3);

    validReasons.forEach((reason, idx) => {
      params.set(`reason${idx + 1}`, reason);
    });
  }

  if (options.isPartial) {
    params.set("partial", "1");
  }

  return params;
}

/**
 * Constructs the full extension warning page URL with query parameters.
 */
export function createWarningPageUrl(
  options: WarningUrlOptions,
  getRuntimeUrl?: (path: string) => string
): string {
  const params = buildWarningUrlParams(options);
  const getUrl =
    getRuntimeUrl ||
    (typeof chrome !== "undefined" && chrome.runtime?.getURL
      ? (path: string) => chrome.runtime.getURL(path)
      : (path: string) => path);

  const base = getUrl("warning.html");
  let urlObj: URL;
  try {
    urlObj = new URL(base);
  } catch {
    // If base is a relative path (e.g. in standalone test without chrome.runtime)
    return `${base}?${params.toString()}`;
  }

  urlObj.search = params.toString();
  return urlObj.toString();
}

/**
 * Triggers popup-initiated tab shielding by navigating the active tab to the warning page.
 */
export async function openShieldInterstitial(
  warningUrl: string,
  tabsApi?: typeof chrome.tabs
): Promise<boolean> {
  if (!warningUrl) return false;
  const api = tabsApi || (typeof chrome !== "undefined" ? chrome.tabs : undefined);

  if (api && typeof api.query === "function") {
    try {
      const [tab] = await api.query({ active: true, currentWindow: true });
      if (tab?.id && typeof api.update === "function") {
        await api.update(tab.id, { url: warningUrl });
        return true;
      }
      if (typeof api.create === "function") {
        await api.create({ url: warningUrl });
        return true;
      }
    } catch (err) {
      console.error("[warningIntegration] Failed to navigate tab:", err);
      return false;
    }
  }

  // Fallback for non-extension environments (manual testing)
  try {
    window.open(warningUrl, "_blank");
    return true;
  } catch {
    return false;
  }
}
