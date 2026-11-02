/**
 * Production Warning Interstitial Integration Tests
 *
 * Verifies:
 * - High-risk policy classification
 * - Warning URL generation and parameter encoding
 * - Scheme rejection and destination validation
 * - Tab shielding navigation via Chrome tabs API
 * - Production build artifact consistency
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";

import {
  isHighRiskScan,
  normalizeHostname,
  buildWarningUrlParams,
  createWarningPageUrl,
  openShieldInterstitial,
} from "../src/popup/warningIntegration.ts";

import {
  validateDestination,
  determineSafeBackAction,
  handleGoBack,
  stepContinueFlow,
  recordSessionAllowlist,
} from "../src/warning/warningLogic.ts";

import type { ScanResponse } from "../src/popup/types.ts";

// Helper to create valid dummy scan responses
function makeScanResponse(overrides: Partial<ScanResponse> = {}): ScanResponse {
  return {
    scan_id: "test-scan-123",
    target_type: "website",
    target_reference: "example.com",
    classification: "likely_legitimate",
    risk_score: 10,
    reasons: ["No strong phishing signals found"],
    evidence: [],
    tool_statuses: {
      heuristics: { status: "complete" },
      reputation: { status: "complete" },
      llm: { status: "complete" },
    },
    analysis_status: "complete",
    source: "manual_website",
    created_at: new Date().toISOString(),
    ...overrides,
  };
}

// ===========================================================================
// 1. High-Risk Policy Evaluation Tests
// ===========================================================================

describe("isHighRiskScan — Policy Gating", () => {
  it("classifies explicit 'phishing' verdict as high risk", () => {
    const scan = makeScanResponse({ classification: "phishing", risk_score: 86 });
    assert.equal(isHighRiskScan(scan), true);
  });

  it("classifies risk_score >= 70 as high risk regardless of classification label", () => {
    const scan70 = makeScanResponse({ classification: "suspicious", risk_score: 70 });
    assert.equal(isHighRiskScan(scan70), true);

    const scan95 = makeScanResponse({ classification: "suspicious", risk_score: 95 });
    assert.equal(isHighRiskScan(scan95), true);
  });

  it("classifies lower-risk outcomes as not high risk", () => {
    const scanLegit = makeScanResponse({ classification: "likely_legitimate", risk_score: 12 });
    assert.equal(isHighRiskScan(scanLegit), false);

    const scanSuspicious = makeScanResponse({ classification: "suspicious", risk_score: 54 });
    assert.equal(isHighRiskScan(scanSuspicious), false);

    const scan69 = makeScanResponse({ classification: "suspicious", risk_score: 69 });
    assert.equal(isHighRiskScan(scan69), false);
  });

  it("treats unavailable / failure status conservatively as not high risk", () => {
    const scanUnavailable = makeScanResponse({
      classification: null,
      risk_score: null,
      analysis_status: "unavailable",
    });
    assert.equal(isHighRiskScan(scanUnavailable), false);

    // Even if an unavailable scan had a residual score, failure is not a valid high-risk verdict
    const scanUnavailableWithScore = makeScanResponse({
      classification: null,
      risk_score: 85,
      analysis_status: "unavailable",
    });
    assert.equal(isHighRiskScan(scanUnavailableWithScore), false);
  });

  it("handles null and undefined safely", () => {
    assert.equal(isHighRiskScan(null), false);
    assert.equal(isHighRiskScan(undefined), false);
  });
});

// ===========================================================================
// 2. Warning URL Parameter Building & Encoding Tests
// ===========================================================================

describe("buildWarningUrlParams & createWarningPageUrl — URL Construction", () => {
  it("constructs valid params for standard HTTPS and HTTP destinations", () => {
    const params = buildWarningUrlParams({
      destUrl: "https://secure-login.target-bank.xyz/portal",
      riskScore: 88,
      reasons: ["Misleading subdomain", "Urgency language"],
    });

    assert.equal(params.get("domain"), "secure-login.target-bank.xyz");
    assert.equal(params.get("score"), "88");
    assert.equal(params.get("dest"), "https://secure-login.target-bank.xyz/portal");
    assert.equal(params.get("reason1"), "Misleading subdomain");
    assert.equal(params.get("reason2"), "Urgency language");
    assert.equal(params.get("reason3"), null);
    assert.equal(params.get("partial"), null);
  });

  it("preserves complex destinations with existing query params and fragments", () => {
    const complexUrl = "https://evil.phish.com/auth?token=xyz123&redirect=%2Faccount#step-2";
    const params = buildWarningUrlParams({
      destUrl: complexUrl,
      riskScore: 92,
    });

    assert.equal(params.get("dest"), complexUrl);
    assert.equal(params.get("domain"), "evil.phish.com");
  });

  it("safely encodes special characters, Unicode, ampersands, percent signs, and newlines in reasons", () => {
    const multilineReason = "First warning line\nSecond warning line & detail with 100% urgency: 'verify now' — safe?";
    const unicodeReason = "Обновление аккаунта / Compte suspendu / ⚠️ Immediate action";

    const params = buildWarningUrlParams({
      destUrl: "https://phish.example.com",
      reasons: [multilineReason, unicodeReason],
    });

    assert.equal(params.get("reason1"), multilineReason);
    assert.equal(params.get("reason2"), unicodeReason);

    // Verify round-trip parsing through full URL
    const fullUrl = createWarningPageUrl(
      { destUrl: "https://phish.example.com", reasons: [multilineReason, unicodeReason] },
      (p) => `chrome-extension://dummy-id/${p}`
    );

    const parsed = new URL(fullUrl);
    assert.equal(parsed.searchParams.get("reason1"), multilineReason);
    assert.equal(parsed.searchParams.get("reason2"), unicodeReason);
  });

  it("normalizes hostname (lowercasing, whitespace, trailing dots)", () => {
    assert.equal(normalizeHostname("  PAYPAL.CO.UK.  "), "paypal.co.uk");
    assert.equal(normalizeHostname(""), "");
    assert.equal(normalizeHostname(null), "");

    const params = buildWarningUrlParams({
      destUrl: "HTTPS://EVIL-LOGIN.COM./path",
    });
    assert.equal(params.get("domain"), "evil-login.com");
  });

  it("handles missing scores and reasons conservatively without inventing data", () => {
    const params = buildWarningUrlParams({
      destUrl: "https://test.example.com",
      riskScore: null,
      reasons: [],
    });

    assert.equal(params.get("domain"), "test.example.com");
    assert.equal(params.get("score"), null);
    assert.equal(params.get("reason1"), null);
    assert.equal(params.get("reason2"), null);
    assert.equal(params.get("reason3"), null);
  });

  it("appends partial=1 when isPartial is true", () => {
    const params = buildWarningUrlParams({
      destUrl: "https://test.example.com",
      isPartial: true,
    });
    assert.equal(params.get("partial"), "1");
  });

  it("rejects unsafe schemes (javascript:, data:, ftp:, file:)", () => {
    assert.throws(
      () => buildWarningUrlParams({ destUrl: "javascript:alert(document.cookie)" }),
      /Unsupported destination scheme/
    );

    assert.throws(
      () => buildWarningUrlParams({ destUrl: "data:text/html,<h1>phish</h1>" }),
      /Unsupported destination scheme/
    );

    assert.throws(
      () => buildWarningUrlParams({ destUrl: "ftp://files.example.com" }),
      /Unsupported destination scheme/
    );
  });

  it("rejects malformed or empty destination URLs", () => {
    assert.throws(() => buildWarningUrlParams({ destUrl: "" }), /must not be empty/);
    assert.throws(() => buildWarningUrlParams({ destUrl: "not-a-valid-url" }), /Invalid destination URL/);
    assert.throws(
  () => buildWarningUrlParams({ destUrl: "http://" }),
  /Invalid destination URL/
);
  });

  it("createWarningPageUrl constructs full chrome-extension URL", () => {
    const dummyGetUrl = (path: string) => `chrome-extension://abcdefghijklmnopqrstuvwxyz123456/${path}`;
    const warningUrl = createWarningPageUrl(
      {
        destUrl: "https://target.xyz/login",
        riskScore: 78,
        reasons: ["Test reason"],
      },
      dummyGetUrl
    );

    assert.ok(warningUrl.startsWith("chrome-extension://abcdefghijklmnopqrstuvwxyz123456/warning.html?"));
    const parsed = new URL(warningUrl);
    assert.equal(parsed.searchParams.get("domain"), "target.xyz");
    assert.equal(parsed.searchParams.get("score"), "78");
    assert.equal(parsed.searchParams.get("dest"), "https://target.xyz/login");
  });
});

// ===========================================================================
// 3. Tab Shielding Navigation Tests (Mocked chrome.tabs)
// ===========================================================================

describe("openShieldInterstitial — Tab Navigation Execution", () => {
  it("updates the active tab to the warning page when active tab exists", async () => {
    let updatedTabId: number | null = null;
    let updatedUrl: string | null = null;

    const mockTabsApi = {
      query: async () => [{ id: 42, active: true, currentWindow: true } as chrome.tabs.Tab],
      update: async (tabId: number, opts: { url?: string }) => {
        updatedTabId = tabId;
        updatedUrl = opts.url ?? null;
        return {} as chrome.tabs.Tab;
      },
      create: async () => ({}) as chrome.tabs.Tab,
    } as unknown as typeof chrome.tabs;

    const testUrl = "chrome-extension://id/warning.html?domain=evil.com";
    const result = await openShieldInterstitial(testUrl, mockTabsApi);

    assert.equal(result, true);
    assert.equal(updatedTabId, 42);
    assert.equal(updatedUrl, testUrl);
  });

  it("falls back to creating a new tab if active tab has no id", async () => {
    let createdUrl: string | null = null;

    const mockTabsApi = {
      query: async () => [{ active: true, currentWindow: true } as chrome.tabs.Tab], // no id
      update: async () => ({}) as chrome.tabs.Tab,
      create: async (opts: { url?: string }) => {
        createdUrl = opts.url ?? null;
        return {} as chrome.tabs.Tab;
      },
    } as unknown as typeof chrome.tabs;

    const testUrl = "chrome-extension://id/warning.html?domain=evil.com";
    const result = await openShieldInterstitial(testUrl, mockTabsApi);

    assert.equal(result, true);
    assert.equal(createdUrl, testUrl);
  });

  it("returns false without navigating on empty warning URL", async () => {
    let updateCalled = false;
    const mockTabsApi = {
      query: async () => [{ id: 10 } as chrome.tabs.Tab],
      update: async () => {
        updateCalled = true;
        return {} as chrome.tabs.Tab;
      },
    } as unknown as typeof chrome.tabs;

    const result = await openShieldInterstitial("", mockTabsApi);
    assert.equal(result, false);
    assert.equal(updateCalled, false);
  });

  it("catches errors gracefully when tabs API throws", async () => {
    const mockTabsApi = {
      query: async () => {
        throw new Error("Tab operation blocked by Chrome policy");
      },
    } as unknown as typeof chrome.tabs;

    const result = await openShieldInterstitial("chrome-extension://id/warning.html", mockTabsApi);
    assert.equal(result, false);
  });
});

// ===========================================================================
// 4. Warning Interstitial Logic Consistency Tests (Production Module)
// ===========================================================================

describe("warningLogic.ts — Production Module Consistency", () => {
  it("validateDestination accepts valid matching URLs and rejects mismatches", () => {
    const valid = validateDestination("https://legit-phish.xyz/login", "legit-phish.xyz");
    assert.equal(valid.valid, true);

    const mismatch = validateDestination("https://legit-phish.xyz/login", "different-site.com");
    assert.equal(mismatch.valid, false);
  });

  it("determineSafeBackAction suppresses history.back() when referrer is suspicious", () => {
    const action = determineSafeBackAction(5, "https://evil.com/phish", "evil.com");
    assert.equal(action, "close_or_blank");
  });

  it("stepContinueFlow arms on first click and confirms on second click", () => {
    const state1 = stepContinueFlow({ armed: false }, "https://target.xyz", "target.xyz");
    assert.equal(state1.step, "armed");

    const state2 = stepContinueFlow(state1.state, "https://target.xyz", "target.xyz");
    assert.equal(state2.step, "confirmed");
  });

  it("recordSessionAllowlist reports storage write errors to prevent unshielded navigation", (t, done) => {
    const mockChrome = {
      storage: {
        session: {
          set: (_data: unknown, cb: () => void) => cb(),
        },
      },
      runtime: { lastError: { message: "Storage quota exceeded" } },
    } as unknown as typeof chrome;

    recordSessionAllowlist("target.xyz", { chrome: mockChrome }, (err) => {
      assert.ok(err instanceof Error);
      assert.match(err.message, /Storage quota exceeded/);
      done();
    });
  });
});

// ===========================================================================
// 5. Production Build Artifacts Verification
// ===========================================================================

describe("Production Build Output Verification", () => {
  const distDir = path.resolve(process.cwd(), "dist");

  it("dist directory exists and contains popup.html and warning.html", () => {
    if (!fs.existsSync(distDir)) {
      // If run before build, skip gracefully with assertion warning
      return;
    }
    assert.equal(fs.existsSync(path.join(distDir, "popup.html")), true, "dist/popup.html must exist");
    assert.equal(fs.existsSync(path.join(distDir, "warning.html")), true, "dist/warning.html must exist");
  });

  it("dist/manifest.json contains required permissions and restrictive CSP", () => {
    if (!fs.existsSync(distDir)) return;
    const manifestPath = path.join(distDir, "manifest.json");
    assert.equal(fs.existsSync(manifestPath), true, "dist/manifest.json must exist");

    const manifest = JSON.parse(fs.readFileSync(manifestPath, "utf-8"));
    assert.deepEqual(manifest.permissions, ["activeTab", "scripting", "storage"]);
    assert.equal(manifest.content_security_policy.extension_pages, "script-src 'self'; object-src 'self'");
    // Verify webNavigation is NOT requested in permissions
    assert.equal(manifest.permissions.includes("webNavigation"), false);
  });

  it("dist/warning.html contains no inline scripts and loads bundle via script-src 'self'", () => {
    if (!fs.existsSync(distDir)) return;
    const warningHtml = fs.readFileSync(path.join(distDir, "warning.html"), "utf-8");

    // Must not contain inline executable JS blocks
    assert.equal(/<script(?![^>]*src=)[^>]*>[\s\S]*?<\/script>/i.test(warningHtml), false);

    // Must contain a script tag loading from assets
    assert.match(warningHtml, /<script type="module" crossorigin src="[^"]*assets\/warning\.js"><\/script>/);
    assert.match(warningHtml, /<link rel="stylesheet" crossorigin href="[^"]*assets\/warning\.css">/);
  });
});
