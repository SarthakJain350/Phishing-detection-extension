import test, { describe } from "node:test";
import assert from "node:assert/strict";
import {
  formatScanTime,
  formatClassificationLabel,
  formatTargetDomain,
} from "../src/popup/historyFormatting.ts";
import { listRecentScans } from "../src/popup/api.ts";
import type { ScanListResponse } from "../src/popup/types.ts";

describe("historyFormatting — formatScanTime", () => {
  const baseNow = new Date("2026-11-02T12:00:00.000Z");

  test("returns 'Just now' for timestamps within 60 seconds", () => {
    const recentIso = new Date(baseNow.getTime() - 30 * 1000).toISOString();
    assert.equal(formatScanTime(recentIso, baseNow), "Just now");
  });

  test("returns 'Xm ago' for timestamps within the current hour", () => {
    const minIso = new Date(baseNow.getTime() - 15 * 60 * 1000).toISOString();
    assert.equal(formatScanTime(minIso, baseNow), "15m ago");
  });

  test("returns 'Xh ago' for timestamps within the current day", () => {
    const hourIso = new Date(baseNow.getTime() - 4 * 60 * 60 * 1000).toISOString();
    assert.equal(formatScanTime(hourIso, baseNow), "4h ago");
  });

  test("returns 'Yesterday' for timestamps roughly 1 day ago", () => {
    const yesterdayIso = new Date(baseNow.getTime() - 25 * 60 * 60 * 1000).toISOString();
    assert.equal(formatScanTime(yesterdayIso, baseNow), "Yesterday");
  });

  test("returns 'Xd ago' for timestamps within 7 days", () => {
    const daysIso = new Date(baseNow.getTime() - 4 * 24 * 60 * 60 * 1000).toISOString();
    assert.equal(formatScanTime(daysIso, baseNow), "4d ago");
  });

  test("handles future or slight client-server clock skew safely", () => {
    const futureIso = new Date(baseNow.getTime() + 10 * 1000).toISOString();
    const result = formatScanTime(futureIso, baseNow);
    assert.ok(typeof result === "string" && result.length > 0);
  });

  test("handles invalid ISO strings safely without crashing", () => {
    const bad = "not-a-valid-date";
    assert.equal(formatScanTime(bad, baseNow), bad);
  });
});

describe("historyFormatting — formatClassificationLabel & formatTargetDomain", () => {
  test("formats classification labels accurately for history badges", () => {
    assert.equal(formatClassificationLabel("phishing"), "Phishing");
    assert.equal(formatClassificationLabel("suspicious"), "Suspicious");
    assert.equal(formatClassificationLabel("likely_legitimate"), "Legitimate");
    assert.equal(formatClassificationLabel(null), "Unclassified");
  });

  test("extracts domain from full URLs and retains naked domains", () => {
    assert.equal(formatTargetDomain("https://secure.bank-login.com/auth/login"), "secure.bank-login.com");
    assert.equal(formatTargetDomain("http://example.com/test?id=123"), "example.com");
    assert.equal(formatTargetDomain("subdomain.example.org"), "subdomain.example.org");
    assert.equal(formatTargetDomain(""), "(unknown)");
  });
});

describe("api — listRecentScans", () => {
  const originalFetch = globalThis.fetch;

  test("successfully requests and returns recent scans list", async () => {
    const mockResponseData: ScanListResponse = {
      items: [
        {
          scan_id: "e5812920-d3a9-4b36-a2b1-5e8d99c43810",
          target_type: "website",
          target_reference: "https://suspicious-bank-login.com",
          classification: "phishing",
          risk_score: 90,
          reasons: ["Known phishing pattern detected."],
          evidence: [],
          tool_statuses: {
            heuristics: { status: "complete" },
            reputation: { status: "partial", reason_code: "provider_not_integrated" },
            llm: { status: "complete" },
          },
          analysis_status: "partial",
          source: "manual_website",
          created_at: new Date().toISOString(),
        },
      ],
      total: 1,
      limit: 20,
      offset: 0,
    };

    let requestedUrl = "";
    globalThis.fetch = async (input: RequestInfo | URL) => {
      requestedUrl = input.toString();
      return new Response(JSON.stringify(mockResponseData), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    try {
      const data = await listRecentScans(10, 5);
      assert.ok(requestedUrl.includes("/api/v1/scans?limit=10&offset=5"));
      assert.equal(data.total, 1);
      assert.equal(data.items.length, 1);
      assert.equal(data.items[0].classification, "phishing");
      assert.equal(data.items[0].risk_score, 90);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("handles empty scans list response gracefully", async () => {
    const mockEmptyData: ScanListResponse = {
      items: [],
      total: 0,
      limit: 20,
      offset: 0,
    };

    globalThis.fetch = async () => {
      return new Response(JSON.stringify(mockEmptyData), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    };

    try {
      const data = await listRecentScans();
      assert.equal(data.total, 0);
      assert.deepEqual(data.items, []);
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("throws descriptive error on request timeout", async () => {
    globalThis.fetch = async () => {
      const error = new DOMException("The operation was aborted due to timeout", "TimeoutError");
      throw error;
    };

    try {
      await assert.rejects(
        async () => {
          await listRecentScans();
        },
        /timed out after 5 seconds/
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("throws descriptive error on network connection failure", async () => {
    globalThis.fetch = async () => {
      throw new TypeError("Failed to fetch");
    };

    try {
      await assert.rejects(
        async () => {
          await listRecentScans();
        },
        /Could not connect to the backend/
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });

  test("handles non-2xx backend HTTP errors with error message", async () => {
    globalThis.fetch = async () => {
      return new Response(
        JSON.stringify({
          error: { code: "SERVICE_UNAVAILABLE", message: "Database is temporarily down" },
        }),
        { status: 503, headers: { "Content-Type": "application/json" } }
      );
    };

    try {
      await assert.rejects(
        async () => {
          await listRecentScans();
        },
        /Database is temporarily down/
      );
    } finally {
      globalThis.fetch = originalFetch;
    }
  });
});
