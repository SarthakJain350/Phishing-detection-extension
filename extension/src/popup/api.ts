import type {
  EmailScanRequest,
  ScanListResponse,
  ScanResponse,
  WebsiteScanRequest,
} from "./types.ts";
import { API_BASE_URL } from "./types.ts";

export const REQUEST_TIMEOUT_MS = 5_000;
export const SCAN_REQUEST_TIMEOUT_MS = 30_000;

/**
 * POST /api/v1/scans/website
 * Submits a website URL for phishing analysis.
 * Throws a descriptive Error on network failure, timeout (5s), or non-2xx response.
 * Never interprets a failure as a safe or legitimate result.
 */
export async function scanWebsite(
  request: WebsiteScanRequest
): Promise<ScanResponse> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/v1/scans/website`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(SCAN_REQUEST_TIMEOUT_MS),
    });
  } catch (err: unknown) {
    if (
      err instanceof DOMException &&
      (err.name === "TimeoutError" || err.name === "AbortError")
    ) {
      throw new Error(
        "The request timed out after 30 seconds. The backend may be unavailable or slow to respond."
      );
    }
    if (err instanceof TypeError) {
      // Network-level failure (refused connection, DNS failure, etc.)
      throw new Error(
        "Could not connect to the backend. Make sure the API server is running on http://127.0.0.1:8000."
      );
    }
    throw new Error(
      "An unexpected error occurred while connecting to the backend."
    );
  }

  if (!response.ok) {
    let errorMessage = `Backend returned HTTP ${response.status}.`;
    try {
      const body = (await response.json()) as {
        error?: { code?: string; message?: string };
      };
      if (body?.error?.message) {
        errorMessage = body.error.message;
      }
    } catch {
      errorMessage = `Backend error: ${response.status} ${response.statusText}`;
    }
    throw new Error(errorMessage);
  }

  return response.json() as Promise<ScanResponse>;
}

/**
 * POST /api/v1/scans/email
 * Submits extracted email indicators for phishing analysis.
 * Throws a descriptive Error on network failure, timeout (30s), or non-2xx response.
 * Never interprets a failure as a safe or legitimate result.
 */
export async function scanEmail(
  request: EmailScanRequest
): Promise<ScanResponse> {
  let response: Response;
  try {
    response = await fetch(`${API_BASE_URL}/api/v1/scans/email`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(request),
      signal: AbortSignal.timeout(SCAN_REQUEST_TIMEOUT_MS),
    });
  } catch (err: unknown) {
    if (
      err instanceof DOMException &&
      (err.name === "TimeoutError" || err.name === "AbortError")
    ) {
      throw new Error(
        "The request timed out after 30 seconds. The backend may be unavailable or slow to respond."
      );
    }
    if (err instanceof TypeError) {
      throw new Error(
        "Could not connect to the backend. Make sure the API server is running on http://127.0.0.1:8000."
      );
    }
    throw new Error(
      "An unexpected error occurred while connecting to the backend."
    );
  }

  if (!response.ok) {
    let errorMessage = `Backend returned HTTP ${response.status}.`;
    try {
      const body = (await response.json()) as {
        error?: { code?: string; message?: string };
        detail?: string;
      };
      if (body?.error?.message) {
        errorMessage = body.error.message;
      } else if (body?.detail) {
        errorMessage = body.detail;
      }
    } catch {
      errorMessage = `Backend error: ${response.status} ${response.statusText}`;
    }
    throw new Error(errorMessage);
  }

  return response.json() as Promise<ScanResponse>;
}

export interface GmailScanResponseResult {
  status: "ok" | "error";
  code?: string;
  detail?: string;
  data?: ScanResponse;
}

/**
 * Sends a SCAN_GMAIL message to the background service worker to trigger
 * extraction and backend email analysis.
 */
export async function requestGmailScan(
  optInGemini: boolean = false
): Promise<GmailScanResponseResult> {
  return new Promise((resolve) => {
    try {
      chrome.runtime.sendMessage(
        { type: "SCAN_GMAIL", optInGemini },
        (response: GmailScanResponseResult | undefined) => {
          if (chrome.runtime.lastError) {
            resolve({
              status: "error",
              code: "content_script_unavailable",
              detail: chrome.runtime.lastError.message,
            });
            return;
          }
          if (!response) {
            resolve({
              status: "error",
              code: "extraction_failed",
              detail: "No response received from background service worker.",
            });
            return;
          }
          resolve(response);
        }
      );
    } catch (err: unknown) {
      resolve({
        status: "error",
        code: "content_script_unavailable",
        detail: err instanceof Error ? err.message : String(err),
      });
    }
  });
}

/**
 * GET /api/v1/scans
 * Retrieves paginated recent scan history from backend.
 * Throws a descriptive Error on network failure, timeout (5s), or non-2xx response.
 */
export async function listRecentScans(
  limit: number = 20,
  offset: number = 0
): Promise<ScanListResponse> {
  let response: Response;
  try {
    response = await fetch(
      `${API_BASE_URL}/api/v1/scans?limit=${encodeURIComponent(limit)}&offset=${encodeURIComponent(offset)}`,
      {
        method: "GET",
        headers: { Accept: "application/json" },
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      }
    );
  } catch (err: unknown) {
    if (
      err instanceof DOMException &&
      (err.name === "TimeoutError" || err.name === "AbortError")
    ) {
      throw new Error(
        "The request timed out after 5 seconds. The backend may be unavailable or slow to respond."
      );
    }
    if (err instanceof TypeError) {
      throw new Error(
        "Could not connect to the backend. Make sure the API server is running on http://127.0.0.1:8000."
      );
    }
    throw new Error(
      "An unexpected error occurred while connecting to the backend."
    );
  }

  if (!response.ok) {
    let errorMessage = `Backend returned HTTP ${response.status}.`;
    try {
      const body = (await response.json()) as {
        error?: { code?: string; message?: string };
      };
      if (body?.error?.message) {
        errorMessage = body.error.message;
      }
    } catch {
      errorMessage = `Backend error: ${response.status} ${response.statusText}`;
    }
    throw new Error(errorMessage);
  }

  return response.json() as Promise<ScanListResponse>;
}

export async function clearScanHistory(): Promise<{
  message: string;
  deleted_count: number;
}> {
  let response: Response;

  try {
    response = await fetch(`${API_BASE_URL}/api/v1/scans`, {
      method: "DELETE",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
  } catch (err: unknown) {
    if (
      err instanceof DOMException &&
      (err.name === "TimeoutError" || err.name === "AbortError")
    ) {
      throw new Error(
        "The request timed out after 5 seconds. Please try again."
      );
    }

    if (err instanceof TypeError) {
      throw new Error(
        "Could not connect to the backend. Make sure the API server is running."
      );
    }

    throw new Error(
      "An unexpected error occurred while clearing scan history."
    );
  }

  if (!response.ok) {
    let errorMessage = `Backend returned HTTP ${response.status}.`;

    try {
      const body = (await response.json()) as {
        detail?: string;
        error?: { message?: string };
      };

      errorMessage =
        body?.detail ||
        body?.error?.message ||
        errorMessage;
    } catch {
      errorMessage = `Backend error: ${response.status} ${response.statusText}`;
    }

    throw new Error(errorMessage);
  }

  return response.json() as Promise<{
    message: string;
    deleted_count: number;
  }>;
}

/**
 * GET /api/v1/health
 * Returns true if the backend liveness check passes.
 */
export async function checkBackendHealth(): Promise<boolean> {
  try {
    // Use the root health alias (no /api/v1 prefix) to avoid extra path length.
    const res = await fetch(`${API_BASE_URL}/health`, {
      signal: AbortSignal.timeout(5_000),
    });
    return res.ok;
  } catch {
    return false;
  }
}
