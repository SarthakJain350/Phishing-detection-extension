/**
 * Gmail Background Service Worker Messaging Tests
 *
 * Verifies:
 * - Successful extraction + backend email scan forwarding
 * - Rejection when active tab is missing or not Gmail
 * - Content script unavailable / messaging errors
 * - Extraction failure mapping (no_elements_found -> no_open_email, etc.)
 * - Extraction timeout after 5 seconds
 * - Malformed payload validation failure
 * - Concurrent scan rejection on the same tab
 * - Fresh scan allowed after prior scan completes
 * - Backend unavailable (network error / timeout) mapping
 * - Backend HTTP error mapping
 * - opt_in_gemini flag correctly passed to backend request
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  handleScanGmailMessage,
  isGmailUrl,
  isValidSuccessPayload,
  mapExtractionReason,
  pendingScans,
} from "../src/background.ts";
import type {
  EmailScanRequest,
  ScanResponse,
} from "../src/popup/types.ts";

function createMockScanResponse(overrides: Partial<ScanResponse> = {}): ScanResponse {
  return {
    scan_id: "11111111-2222-3333-4444-555555555555",
    target_type: "email",
    target_reference: "paypal-security-alert.com",
    classification: "phishing",
    risk_score: 85,
    reasons: ["Suspicious urgent language in subject", "Misleading links detected"],
    evidence: [
      {
        type: "urgent_call_to_action",
        source: "heuristics",
        severity: "high",
        explanation: "Immediate action requested regarding account suspension.",
      },
    ],
    tool_statuses: {
      heuristics: { status: "complete" },
      reputation: { status: "unavailable", reason_code: "provider_not_integrated" },
      llm: { status: "unavailable", reason_code: "opt_in_required" },
    },
    analysis_status: "partial",
    source: "gmail",
    created_at: new Date().toISOString(),
    ...overrides,
  };
}

describe("Pure Helper Functions", () => {
  it("isGmailUrl identifies valid mail.google.com URLs and rejects others", () => {
    assert.equal(isGmailUrl("https://mail.google.com/mail/u/0/#inbox/FMfcg"), true);
    assert.equal(isGmailUrl("https://mail.google.com/"), true);
    assert.equal(isGmailUrl("https://google.com/mail"), false);
    assert.equal(isGmailUrl("https://evil-mail.google.com/"), false);
    assert.equal(isGmailUrl("http://mail.google.com/"), false);
    assert.equal(isGmailUrl(""), false);
    assert.equal(isGmailUrl(undefined), false);
  });

  it("mapExtractionReason correctly maps reasons to taxonomy error codes", () => {
    assert.equal(mapExtractionReason("no_elements_found"), "no_open_email");
    assert.equal(mapExtractionReason("content_script_unavailable"), "content_script_unavailable");
    assert.equal(mapExtractionReason("timeout"), "timeout");
    assert.equal(mapExtractionReason("other_reason"), "extraction_failed");
  });

  it("isValidSuccessPayload verifies payload structure and types", () => {
    const valid = {
      success: true,
      subject: "Test Subject",
      sender: "sender@example.com",
      bodyText: "Body content",
      links: ["https://example.com/link"],
    };
    assert.equal(isValidSuccessPayload(valid), true);

    assert.equal(isValidSuccessPayload(null), false);
    assert.equal(isValidSuccessPayload({ success: false }), false);
    assert.equal(isValidSuccessPayload({ ...valid, subject: 123 }), false);
    assert.equal(isValidSuccessPayload({ ...valid, links: "not-an-array" }), false);
  });
});

describe("Gmail Background Message Orchestration", () => {
  it("successfully extracts and returns backend scan response", async () => {
    const mockTabsApi = {
      query: (_queryInfo: any, callback: (result: any[]) => void) => {
        callback([{ id: 101, url: "https://mail.google.com/mail/u/0/#inbox/1" }]);
      },
      sendMessage: (
        _tabId: number,
        _message: any,
        callback: (response: any) => void
      ) => {
        callback({
          success: true,
          subject: "Urgent: Verify Your Account",
          sender: "support@paypal-security-alert.com",
          bodyText: "Click the link below immediately.",
          links: ["https://paypal-security-alert.com/login"],
        });
      },
    } as any;

    let receivedPayload: EmailScanRequest | null = null;
    const mockScanEmailFn = async (req: EmailScanRequest): Promise<ScanResponse> => {
      receivedPayload = req;
      return createMockScanResponse();
    };

    const result = await handleScanGmailMessage(
      { type: "SCAN_GMAIL", optInGemini: false },
      { tabsApi: mockTabsApi, scanEmailFn: mockScanEmailFn }
    );

    assert.equal(result.status, "ok");
    if (result.status === "ok") {
      assert.equal(result.data.target_type, "email");
      assert.equal(result.data.classification, "phishing");
      assert.equal(result.data.risk_score, 85);
    }

    assert.ok(receivedPayload);
    assert.equal(receivedPayload!.subject, "Urgent: Verify Your Account");
    assert.equal(receivedPayload!.sender, "support@paypal-security-alert.com");
    assert.equal(receivedPayload!.opt_in_gemini, false);
    assert.equal(pendingScans.has(101), false, "Pending scans entry must be cleared");
  });

  it("passes optInGemini=true when explicitly requested by user", async () => {
    const mockTabsApi = {
      query: (_queryInfo: any, callback: (result: any[]) => void) => {
        callback([{ id: 102, url: "https://mail.google.com/mail/u/0/#inbox/2" }]);
      },
      sendMessage: (
        _tabId: number,
        _message: any,
        callback: (response: any) => void
      ) => {
        callback({
          success: true,
          subject: "Newsletter",
          sender: "news@safe.com",
          bodyText: "Read our weekly updates.",
          links: [],
        });
      },
    } as any;

    let receivedPayload: EmailScanRequest | null = null;
    const mockScanEmailFn = async (req: EmailScanRequest): Promise<ScanResponse> => {
      receivedPayload = req;
      return createMockScanResponse({ classification: "likely_legitimate", risk_score: 5 });
    };

    const result = await handleScanGmailMessage(
      { type: "SCAN_GMAIL", optInGemini: true },
      { tabsApi: mockTabsApi, scanEmailFn: mockScanEmailFn }
    );

    assert.equal(result.status, "ok");
    assert.ok(receivedPayload);
    assert.equal(receivedPayload!.opt_in_gemini, true);
    assert.equal(pendingScans.has(102), false);
  });

  it("returns no_active_gmail_tab when active tab is not Gmail", async () => {
    const mockTabsApi = {
      query: (_queryInfo: any, callback: (result: any[]) => void) => {
        callback([{ id: 103, url: "https://github.com/project" }]);
      },
    } as any;

    const result = await handleScanGmailMessage(
      { type: "SCAN_GMAIL" },
      { tabsApi: mockTabsApi }
    );

    assert.equal(result.status, "error");
    if (result.status === "error") {
      assert.equal(result.code, "no_active_gmail_tab");
    }
    assert.equal(pendingScans.has(103), false);
  });

  it("returns no_active_gmail_tab when no active tab exists", async () => {
    const mockTabsApi = {
      query: (_queryInfo: any, callback: (result: any[]) => void) => {
        callback([]);
      },
    } as any;

    const result = await handleScanGmailMessage(
      { type: "SCAN_GMAIL" },
      { tabsApi: mockTabsApi }
    );

    assert.equal(result.status, "error");
    if (result.status === "error") {
      assert.equal(result.code, "no_active_gmail_tab");
    }
  });

  it("returns content_script_unavailable when runtime.lastError is set", async () => {
    let runtimeLastError: any = null;
    const mockRuntimeApi = {
      get lastError() {
        return runtimeLastError;
      },
    } as any;

    const mockTabsApi = {
      query: (_queryInfo: any, callback: (result: any[]) => void) => {
        callback([{ id: 104, url: "https://mail.google.com/mail/u/0/#inbox/4" }]);
      },
      sendMessage: (
        _tabId: number,
        _message: any,
        callback: (response: any) => void
      ) => {
        // Trigger runtime.lastError during sendMessage callback
        runtimeLastError = { message: "Could not establish connection. Receiving end does not exist." };
        callback(undefined);
      },
    } as any;

    const result = await handleScanGmailMessage(
      { type: "SCAN_GMAIL" },
      { tabsApi: mockTabsApi, runtimeApi: mockRuntimeApi }
    );

    assert.equal(result.status, "error");
    if (result.status === "error") {
      assert.equal(result.code, "content_script_unavailable");
    }
    assert.equal(pendingScans.has(104), false);
  });

  it("returns content_script_unavailable when tabs.sendMessage throws synchronously", async () => {
    const mockTabsApi = {
      query: (_queryInfo: any, callback: (result: any[]) => void) => {
        callback([{ id: 105, url: "https://mail.google.com/mail/u/0/#inbox/5" }]);
      },
      sendMessage: () => {
        throw new Error("Target tab closed unexpectedly");
      },
    } as any;

    const result = await handleScanGmailMessage(
      { type: "SCAN_GMAIL" },
      { tabsApi: mockTabsApi }
    );

    assert.equal(result.status, "error");
    if (result.status === "error") {
      assert.equal(result.code, "content_script_unavailable");
    }
    assert.equal(pendingScans.has(105), false);
  });

  it("returns no_open_email when extraction reports no_elements_found", async () => {
    const mockTabsApi = {
      query: (_queryInfo: any, callback: (result: any[]) => void) => {
        callback([{ id: 106, url: "https://mail.google.com/mail/u/0/#inbox" }]);
      },
      sendMessage: (
        _tabId: number,
        _message: any,
        callback: (response: any) => void
      ) => {
        callback({ success: false, reason: "no_elements_found" });
      },
    } as any;

    const result = await handleScanGmailMessage(
      { type: "SCAN_GMAIL" },
      { tabsApi: mockTabsApi }
    );

    assert.equal(result.status, "error");
    if (result.status === "error") {
      assert.equal(result.code, "no_open_email");
    }
    assert.equal(pendingScans.has(106), false);
  });

  it("returns timeout when content script does not respond within timeout period", async () => {
    const mockTabsApi = {
      query: (_queryInfo: any, callback: (result: any[]) => void) => {
        callback([{ id: 107, url: "https://mail.google.com/mail/u/0/#inbox/7" }]);
      },
      sendMessage: (
        _tabId: number,
        _message: any,
        _callback: (response: any) => void
      ) => {
        // Deliberately do not call callback to exercise timeout
      },
    } as any;

    const result = await handleScanGmailMessage(
      { type: "SCAN_GMAIL" },
      { tabsApi: mockTabsApi, timeoutMs: 50 }
    );

    assert.equal(result.status, "error");
    if (result.status === "error") {
      assert.equal(result.code, "timeout");
    }
    assert.equal(pendingScans.has(107), false);
  });

  it("returns invalid_payload when extraction result fails schema validation", async () => {
    const mockTabsApi = {
      query: (_queryInfo: any, callback: (result: any[]) => void) => {
        callback([{ id: 108, url: "https://mail.google.com/mail/u/0/#inbox/8" }]);
      },
      sendMessage: (
        _tabId: number,
        _message: any,
        callback: (response: any) => void
      ) => {
        callback({ success: true, subject: 12345, links: "not-an-array" });
      },
    } as any;

    const result = await handleScanGmailMessage(
      { type: "SCAN_GMAIL" },
      { tabsApi: mockTabsApi }
    );

    assert.equal(result.status, "error");
    if (result.status === "error") {
      assert.equal(result.code, "invalid_payload");
    }
    assert.equal(pendingScans.has(108), false);
  });

  it("rejects concurrent scan requests on the same tab", async () => {
    let completeFirstExtraction: () => void;
    const mockTabsApi = {
      query: (_queryInfo: any, callback: (result: any[]) => void) => {
        callback([{ id: 109, url: "https://mail.google.com/mail/u/0/#inbox/9" }]);
      },
      sendMessage: (
        _tabId: number,
        _message: any,
        callback: (response: any) => void
      ) => {
        completeFirstExtraction = () => {
          callback({
            success: true,
            subject: "Subject",
            sender: "sender@domain.com",
            bodyText: "Body text",
            links: [],
          });
        };
      },
    } as any;

    const mockScanEmailFn = async (): Promise<ScanResponse> => {
      return createMockScanResponse();
    };

    // Start first scan (in-flight)
    const scan1Promise = handleScanGmailMessage(
      { type: "SCAN_GMAIL" },
      { tabsApi: mockTabsApi, scanEmailFn: mockScanEmailFn }
    );

    // Concurrently trigger second scan on same tab
    const scan2Result = await handleScanGmailMessage(
      { type: "SCAN_GMAIL" },
      { tabsApi: mockTabsApi, scanEmailFn: mockScanEmailFn }
    );

    assert.equal(scan2Result.status, "error");
    if (scan2Result.status === "error") {
      assert.equal(scan2Result.code, "concurrent_scan");
    }

    // Now resolve first scan
    completeFirstExtraction!();
    const scan1Result = await scan1Promise;
    assert.equal(scan1Result.status, "ok");
    assert.equal(pendingScans.has(109), false);
  });

  it("executes a fresh extraction when a new deliberate request occurs after prior completion", async () => {
    let callCount = 0;
    const mockTabsApi = {
      query: (_queryInfo: any, callback: (result: any[]) => void) => {
        callback([{ id: 110, url: "https://mail.google.com/mail/u/0/#inbox/10" }]);
      },
      sendMessage: (
        _tabId: number,
        _message: any,
        callback: (response: any) => void
      ) => {
        callCount++;
        callback({
          success: true,
          subject: `Email #${callCount}`,
          sender: "test@example.com",
          bodyText: "Body",
          links: [],
        });
      },
    } as any;

    let backendCount = 0;
    const mockScanEmailFn = async (_req: EmailScanRequest): Promise<ScanResponse> => {
      backendCount++;
      return createMockScanResponse({ scan_id: `00000000-0000-0000-0000-00000000000${backendCount}` });
    };

    // First scan
    const res1 = await handleScanGmailMessage(
      { type: "SCAN_GMAIL" },
      { tabsApi: mockTabsApi, scanEmailFn: mockScanEmailFn }
    );
    assert.equal(res1.status, "ok");
    assert.equal(callCount, 1);
    assert.equal(backendCount, 1);
    assert.equal(pendingScans.has(110), false);

    // Second deliberate scan
    const res2 = await handleScanGmailMessage(
      { type: "SCAN_GMAIL" },
      { tabsApi: mockTabsApi, scanEmailFn: mockScanEmailFn }
    );
    assert.equal(res2.status, "ok");
    assert.equal(callCount, 2, "Second scan must execute fresh content script extraction");
    assert.equal(backendCount, 2, "Second scan must create a fresh backend scan record");
    assert.equal(pendingScans.has(110), false);
  });

  it("maps network connection failures to backend_unavailable", async () => {
    const mockTabsApi = {
      query: (_queryInfo: any, callback: (result: any[]) => void) => {
        callback([{ id: 111, url: "https://mail.google.com/mail/u/0/#inbox/11" }]);
      },
      sendMessage: (
        _tabId: number,
        _message: any,
        callback: (response: any) => void
      ) => {
        callback({
          success: true,
          subject: "Title",
          sender: "user@domain.com",
          bodyText: "Text",
          links: [],
        });
      },
    } as any;

    const mockFailingScanEmail = async (): Promise<ScanResponse> => {
      throw new Error("Could not connect to the backend. Make sure the API server is running on http://127.0.0.1:8000.");
    };

    const result = await handleScanGmailMessage(
      { type: "SCAN_GMAIL" },
      { tabsApi: mockTabsApi, scanEmailFn: mockFailingScanEmail }
    );

    assert.equal(result.status, "error");
    if (result.status === "error") {
      assert.equal(result.code, "backend_unavailable");
      assert.match(result.detail!, /Could not connect/);
    }
    assert.equal(pendingScans.has(111), false);
  });

  it("maps backend HTTP validation/service errors to backend_error", async () => {
    const mockTabsApi = {
      query: (_queryInfo: any, callback: (result: any[]) => void) => {
        callback([{ id: 112, url: "https://mail.google.com/mail/u/0/#inbox/12" }]);
      },
      sendMessage: (
        _tabId: number,
        _message: any,
        callback: (response: any) => void
      ) => {
        callback({
          success: true,
          subject: "Title",
          sender: "user@domain.com",
          bodyText: "Text",
          links: [],
        });
      },
    } as any;

    const mockHttpErrorScanEmail = async (): Promise<ScanResponse> => {
      throw new Error("Backend returned HTTP 400. Maximum of 10 links allowed per email scan.");
    };

    const result = await handleScanGmailMessage(
      { type: "SCAN_GMAIL" },
      { tabsApi: mockTabsApi, scanEmailFn: mockHttpErrorScanEmail }
    );

    assert.equal(result.status, "error");
    if (result.status === "error") {
      assert.equal(result.code, "backend_error");
      assert.match(result.detail!, /Maximum of 10 links/);
    }
    assert.equal(pendingScans.has(112), false);
  });
});
