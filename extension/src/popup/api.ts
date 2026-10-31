import type { ScanResponse, WebsiteScanRequest } from "./types";
import { API_BASE_URL } from "./types";

export const REQUEST_TIMEOUT_MS = 5_000;

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
      signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
    });
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
 * GET /api/v1/health
 * Returns true if the backend liveness check passes.
 */
export async function checkBackendHealth(): Promise<boolean> {
  try {
    const res = await fetch(`${API_BASE_URL}/api/v1/health`, {
      signal: AbortSignal.timeout(5_000),
    });
    return res.ok;
  } catch {
    return false;
  }
}
