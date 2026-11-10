/// <reference types="chrome"/>
/**
 * Background service worker — Phishing Attack Detector
 * =====================================================
 * Stage 3: Backend Integration and Gmail Scanning Service Worker
 *
 * This service worker handles:
 *   SCAN_GMAIL messages from the popup by:
 *   1. Validating that the active tab is on https://mail.google.com/*.
 *   2. Guarding against concurrent scans on the same tab.
 *   3. Forwarding EXTRACT_GMAIL to the static content script (content/gmailExtract.js).
 *   4. Enforcing a 5-second timeout and handling messaging failures.
 *   5. Submitting the extracted email indicators to the backend POST /api/v1/scans/email.
 *   6. Returning the verified backend ScanResponse directly to the caller.
 *
 * Privacy boundaries:
 *   - Only bounded metadata is sent (subject <= 256, sender <= 256, body <= 3000, links <= 10).
 *   - No mailbox-wide scanning.
 *   - opt_in_gemini defaults to false unless explicitly true.
 *   - No completed scan results are cached; each deliberate scan creates a fresh record.
 */

import { scanEmail } from "./popup/api.ts";
import type { EmailScanRequest, ScanResponse } from "./popup/types.ts";

// ---------------------------------------------------------------------------
// Error Codes & Types
// ---------------------------------------------------------------------------

export type ScanErrorCode =
  | "no_active_gmail_tab"
  | "no_open_email"
  | "content_script_unavailable"
  | "extraction_failed"
  | "timeout"
  | "invalid_payload"
  | "concurrent_scan"
  | "backend_unavailable"
  | "backend_error";

export interface GmailExtractionSuccess {
  success: true;
  subject: string;
  sender: string;
  bodyText: string;
  links: string[];
}

export interface GmailExtractionError {
  success: false;
  reason: string;
}

export type GmailExtractionResult =
  | GmailExtractionSuccess
  | GmailExtractionError;

export type GmailScanResult =
  | { status: "ok"; data: ScanResponse }
  | { status: "error"; code: ScanErrorCode; detail?: string };

// ---------------------------------------------------------------------------
// In-flight scan guard (per-tab)
// ---------------------------------------------------------------------------

export const pendingScans = new Map<number, Promise<GmailScanResult>>();

// ---------------------------------------------------------------------------
// Pure Helpers
// ---------------------------------------------------------------------------

export function makeError(code: ScanErrorCode, detail?: string): GmailScanResult {
  return { status: "error", code, detail };
}

export function isGmailUrl(url: string | undefined): boolean {
  if (!url) return false;
  return /^https:\/\/mail\.google\.com\//.test(url);
}

export function mapExtractionReason(reason: string): ScanErrorCode {
  if (reason === "no_elements_found") return "no_open_email";
  if (reason === "content_script_unavailable") return "content_script_unavailable";
  if (reason === "timeout") return "timeout";
  return "extraction_failed";
}

export function isValidSuccessPayload(p: unknown): p is GmailExtractionSuccess {
  if (!p || typeof p !== "object") return false;
  const obj = p as Record<string, unknown>;
  return (
    obj.success === true &&
    typeof obj.subject === "string" &&
    typeof obj.sender === "string" &&
    typeof obj.bodyText === "string" &&
    Array.isArray(obj.links)
  );
}

// ---------------------------------------------------------------------------
// Execution Options (for testability)
// ---------------------------------------------------------------------------

export interface HandleScanGmailOptions {
  tabsApi?: typeof chrome.tabs;
  runtimeApi?: typeof chrome.runtime;
  scanEmailFn?: (req: EmailScanRequest) => Promise<ScanResponse>;
  timeoutMs?: number;
}

// ---------------------------------------------------------------------------
// Content Script Extraction Runner
// ---------------------------------------------------------------------------

export function performExtraction(
  tabId: number,
  options: HandleScanGmailOptions = {}
): Promise<
  | { success: true; data: GmailExtractionSuccess }
  | { success: false; error: GmailScanResult }
> {
  const tabsApi = options.tabsApi ?? (typeof chrome !== "undefined" ? chrome.tabs : undefined);
  const runtimeApi = options.runtimeApi ?? (typeof chrome !== "undefined" ? chrome.runtime : undefined);
  const timeoutMs = options.timeoutMs ?? 5_000;

  return new Promise((resolve) => {
    let settled = false;
    let timeoutHandle: ReturnType<typeof setTimeout> | null = null;

    function settle(
      result:
        | { success: true; data: GmailExtractionSuccess }
        | { success: false; error: GmailScanResult }
    ) {
      if (settled) return;
      settled = true;
      if (timeoutHandle !== null) {
        clearTimeout(timeoutHandle);
        timeoutHandle = null;
      }
      resolve(result);
    }

    timeoutHandle = setTimeout(() => {
      settle({
        success: false,
        error: makeError(
          "timeout",
          "Content script did not respond within the timeout period"
        ),
      });
    }, timeoutMs);

    if (!tabsApi?.sendMessage) {
      settle({
        success: false,
        error: makeError(
          "content_script_unavailable",
          "tabs.sendMessage API is unavailable"
        ),
      });
      return;
    }

    try {
      tabsApi.sendMessage(
        tabId,
        { type: "EXTRACT_GMAIL" },
        (response: GmailExtractionResult | undefined) => {
          if (runtimeApi?.lastError) {
            settle({
              success: false,
              error: makeError(
                "content_script_unavailable",
                runtimeApi.lastError.message
              ),
            });
            return;
          }

          if (!response) {
            settle({
              success: false,
              error: makeError(
                "extraction_failed",
                "Empty response from content script"
              ),
            });
            return;
          }

          if (!response.success) {
            const code = mapExtractionReason(response.reason ?? "");
            settle({
              success: false,
              error: makeError(code, response.reason),
            });
            return;
          }

          if (!isValidSuccessPayload(response)) {
            settle({
              success: false,
              error: makeError(
                "invalid_payload",
                "Response payload failed shape validation"
              ),
            });
            return;
          }

          settle({ success: true, data: response });
        }
      );
    } catch (err: unknown) {
      settle({
        success: false,
        error: makeError("content_script_unavailable", String(err)),
      });
    }
  });
}

// ---------------------------------------------------------------------------
// Orchestrated Gmail Scan Handler (Extraction + Backend API Call)
// ---------------------------------------------------------------------------

export async function handleScanGmailMessage(
  msg: { type?: string; optInGemini?: boolean },
  options: HandleScanGmailOptions = {}
): Promise<GmailScanResult> {
  const tabsApi = options.tabsApi ?? (typeof chrome !== "undefined" ? chrome.tabs : undefined);
  const scanEmailFn = options.scanEmailFn ?? scanEmail;

  if (!tabsApi?.query) {
    return makeError("no_active_gmail_tab", "tabs.query API is unavailable");
  }

  // 1. Resolve active tab
  let tabs: chrome.tabs.Tab[];
  try {
    tabs = await new Promise<chrome.tabs.Tab[]>((resolve, reject) => {
      tabsApi.query({ active: true, currentWindow: true }, (result) => {
        const runtimeApi = options.runtimeApi ?? (typeof chrome !== "undefined" ? chrome.runtime : undefined);
        if (runtimeApi?.lastError) {
          reject(runtimeApi.lastError);
        } else {
          resolve(result);
        }
      });
    });
  } catch {
    return makeError("no_active_gmail_tab", "Failed to query active tab");
  }

  const tab = tabs[0];
  if (!tab?.id) {
    return makeError("no_active_gmail_tab", "No active tab found");
  }

  const tabId = tab.id;
  if (!isGmailUrl(tab.url)) {
    return makeError("no_active_gmail_tab", "Active tab is not a Gmail page");
  }

  // 2. Reject concurrent scans on the same tab
  if (pendingScans.has(tabId)) {
    return makeError(
      "concurrent_scan",
      `Tab ${tabId} already has a pending scan in progress`
    );
  }

  // 3. Execute extraction and backend call inside try/finally to guarantee cleanup
  const scanPromise = (async (): Promise<GmailScanResult> => {
    try {
      const extraction = await performExtraction(tabId, options);
      if (!extraction.success) {
        return extraction.error;
      }

      const extracted = extraction.data;
      const scanRequest: EmailScanRequest = {
        sender: extracted.sender || null,
        subject: extracted.subject || null,
        body_text: extracted.bodyText || null,
        links: extracted.links,
        source: "gmail",
        opt_in_gemini: msg.optInGemini === true,
      };

      try {
        const backendResponse = await scanEmailFn(scanRequest);
        return { status: "ok", data: backendResponse };
      } catch (err: unknown) {
        const msgText = err instanceof Error ? err.message : String(err);
        const isUnavailable =
          msgText.includes("Could not connect") ||
          msgText.includes("timed out") ||
          msgText.includes("503") ||
          msgText.includes("unavailable");
        return makeError(
          isUnavailable ? "backend_unavailable" : "backend_error",
          msgText
        );
      }
    } finally {
      pendingScans.delete(tabId);
    }
  })();

  pendingScans.set(tabId, scanPromise);

  try {
    return await scanPromise;
  } catch (err: unknown) {
    pendingScans.delete(tabId);
    return makeError("extraction_failed", String(err));
  }
}

// ---------------------------------------------------------------------------
// Service Worker Message Listener
// ---------------------------------------------------------------------------

if (
  typeof chrome !== "undefined" &&
  chrome.runtime?.onMessage?.addListener
) {
  chrome.runtime.onMessage.addListener(
    (msg: { type?: string; optInGemini?: boolean }, _sender, sendResponse) => {
      if (!msg || msg.type !== "SCAN_GMAIL") {
        return false;
      }

      handleScanGmailMessage(msg).then((result) => {
        sendResponse(result);
      });

      return true;
    }
  );
}
