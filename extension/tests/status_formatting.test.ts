/**
 * Unit tests for statusFormatting module.
 *
 * Verifies that:
 * 1. 'provider_not_integrated' is clearly distinguished from runtime failures (timeouts, errors).
 * 2. Status table labels display 'Not integrated' for unintegrated checks instead of misleading 'Unavailable'.
 * 3. Partial analysis summary explains unintegrated checks as advisory without sounding like an operational crash.
 * 4. Actual runtime errors or timeouts produce explicit failure messaging.
 * 5. Neither message ever implies a site is guaranteed safe.
 */

import { describe, it } from "node:test";
import assert from "node:assert/strict";

import {
  getToolStatusLabel,
  hasRuntimeCheckFailure,
  hasUnintegratedProvider,
  hasGeminiOptInRequired,
  getPartialAnalysisSummary,
  getClassificationDisplayMeta,
  getAdditionalFindings,
} from "../src/popup/statusFormatting.ts";

import type { EvidenceItem, ToolStatuses } from "../src/popup/types.ts";

describe("statusFormatting — getToolStatusLabel", () => {
  it("displays 'Not integrated' when reason_code is provider_not_integrated", () => {
    assert.equal(
      getToolStatusLabel({ status: "unavailable", reason_code: "provider_not_integrated" }),
      "Not integrated"
    );
  });

  it("displays 'Unavailable' for generic unavailable without provider_not_integrated", () => {
    assert.equal(
      getToolStatusLabel({ status: "unavailable", reason_code: "service_offline" }),
      "Unavailable"
    );
    assert.equal(
      getToolStatusLabel({ status: "unavailable" }),
      "Unavailable"
    );
  });

  it("displays accurate labels for standard status states", () => {
    assert.equal(getToolStatusLabel({ status: "complete" }), "Complete");
    assert.equal(getToolStatusLabel({ status: "timeout" }), "Timed out");
    assert.equal(getToolStatusLabel({ status: "error" }), "Error");
    assert.equal(getToolStatusLabel({ status: "partial" }), "Partial");
  });
});

describe("statusFormatting — hasRuntimeCheckFailure vs hasUnintegratedProvider", () => {
  const unintegratedStatuses: ToolStatuses = {
    heuristics: { status: "complete" },
    reputation: { status: "unavailable", reason_code: "provider_not_integrated" },
    llm: { status: "complete" },
  };

  const timeoutStatuses: ToolStatuses = {
    heuristics: { status: "complete" },
    reputation: { status: "timeout", reason_code: "request_timeout" },
    llm: { status: "complete" },
  };

  const errorStatuses: ToolStatuses = {
    heuristics: { status: "complete" },
    reputation: { status: "unavailable", reason_code: "provider_not_integrated" },
    llm: { status: "error", reason_code: "http_500" },
  };

  it("identifies planned unintegrated provider without marking as runtime failure", () => {
    assert.equal(hasUnintegratedProvider(unintegratedStatuses), true);
    assert.equal(hasRuntimeCheckFailure(unintegratedStatuses), false);
  });

  it("identifies runtime timeout as runtime failure", () => {
    assert.equal(hasRuntimeCheckFailure(timeoutStatuses), true);
    assert.equal(hasUnintegratedProvider(timeoutStatuses), false);
  });

  it("identifies runtime error as runtime failure even if unintegrated provider is also present", () => {
    assert.equal(hasRuntimeCheckFailure(errorStatuses), true);
    assert.equal(hasUnintegratedProvider(errorStatuses), true);
  });

  it("handles undefined toolStatuses safely", () => {
    assert.equal(hasRuntimeCheckFailure(undefined), false);
    assert.equal(hasUnintegratedProvider(undefined), false);
  });
});

describe("statusFormatting — getPartialAnalysisSummary", () => {
  it("produces advisory messaging when check is unintegrated, NOT crash/timeout phrasing", () => {
    const statuses: ToolStatuses = {
      heuristics: { status: "complete" },
      reputation: { status: "unavailable", reason_code: "provider_not_integrated" },
      llm: { status: "complete" },
    };
    const summary = getPartialAnalysisSummary(
      ["Reputation checking is not integrated in this build."],
      statuses
    );

    assert.match(summary, /Reputation checking is not yet integrated/);
    assert.match(summary, /Results are advisory and do not guarantee safety/);
    // Crucial: Must NOT state 'Some checks could not finish' which sounds like a crash
    assert.doesNotMatch(summary, /Some checks could not finish/);
  });

  it("produces explicit failure messaging when an actual runtime failure or timeout occurred", () => {
    const statuses: ToolStatuses = {
      heuristics: { status: "complete" },
      reputation: { status: "timeout", reason_code: "request_timeout" },
      llm: { status: "complete" },
    };
    const summary = getPartialAnalysisSummary(
      ["Reputation lookup timed out and could not be completed."],
      statuses
    );

    assert.match(summary, /Some checks could not finish due to a service timeout or error/);
    assert.match(summary, /Treat this result with caution/);
  });

  it("appends first reason explanation when available", () => {
    const summary = getPartialAnalysisSummary(
      ["Primary risk signal noted."],
      {
        heuristics: { status: "complete" },
        reputation: { status: "unavailable", reason_code: "provider_not_integrated" },
        llm: { status: "complete" },
      }
    );
    assert.match(summary, /Primary risk signal noted\./);
  });
});

describe("statusFormatting — getClassificationDisplayMeta (Null Classification Protection)", () => {
  it("never renders complete analysis with null classification as likely_legitimate", () => {
    const meta = getClassificationDisplayMeta(null, "complete");
    assert.notEqual(meta.visualKey, "likely_legitimate");
    assert.equal(meta.visualKey, "inconclusive");
    assert.equal(meta.label, "Analysis inconclusive");
    assert.equal(meta.cssClass, "classification-badge--unavailable");
  });

  it("renders unavailable status correctly when classification is null", () => {
    const meta = getClassificationDisplayMeta(null, "unavailable");
    assert.equal(meta.visualKey, "unavailable");
    assert.equal(meta.label, "Analysis unavailable");
    assert.equal(meta.cssClass, "classification-badge--unavailable");
  });

  it("renders partial status correctly when classification is null", () => {
    const meta = getClassificationDisplayMeta(null, "partial");
    assert.equal(meta.visualKey, "partial");
    assert.equal(meta.label, "Partial analysis");
    assert.equal(meta.cssClass, "classification-badge--partial");
  });

  it("renders standard classifications accurately", () => {
    const phish = getClassificationDisplayMeta("phishing", "complete");
    assert.equal(phish.visualKey, "phishing");
    assert.equal(phish.label, "Phishing risk detected");

    const suspWeb = getClassificationDisplayMeta("suspicious", "complete", "website");
    assert.equal(suspWeb.label, "Suspicious website");

    const suspEmail = getClassificationDisplayMeta("suspicious", "complete", "email");
    assert.equal(suspEmail.label, "Suspicious email");

    const legit = getClassificationDisplayMeta("likely_legitimate", "complete");
    assert.equal(legit.visualKey, "likely_legitimate");
    assert.equal(legit.label, "No strong phishing signals found");
  });
});

// ---------------------------------------------------------------------------
// New regression tests: opt_in_required vs runtime failure vs unintegrated
// ---------------------------------------------------------------------------

describe("statusFormatting — hasGeminiOptInRequired", () => {
  it("identifies Gemini opt-in disabled state", () => {
    const statuses: ToolStatuses = {
      heuristics: { status: "complete" },
      reputation: { status: "unavailable", reason_code: "provider_not_integrated" },
      llm: { status: "unavailable", reason_code: "opt_in_required" },
    };
    assert.equal(hasGeminiOptInRequired(statuses), true);
  });

  it("does not identify Gemini opt-in when LLM is complete", () => {
    const statuses: ToolStatuses = {
      heuristics: { status: "complete" },
      reputation: { status: "complete" },
      llm: { status: "complete" },
    };
    assert.equal(hasGeminiOptInRequired(statuses), false);
  });

  it("does not identify Gemini opt-in when LLM timed out (different reason)", () => {
    const statuses: ToolStatuses = {
      heuristics: { status: "complete" },
      reputation: { status: "complete" },
      llm: { status: "timeout", reason_code: "request_timeout" },
    };
    assert.equal(hasGeminiOptInRequired(statuses), false);
  });

  it("handles undefined toolStatuses safely", () => {
    assert.equal(hasGeminiOptInRequired(undefined), false);
  });
});

describe("statusFormatting — opt_in_required is NOT a runtime failure", () => {
  it("Gemini opt-in disabled must NOT be treated as a runtime service failure", () => {
    // This is the core bug regression: opt_in_required was classified as a
    // runtime failure, causing the UI to say 'Some checks could not finish due
    // to a service timeout or error' — which is inaccurate for an intentional gate.
    const emailScanStatuses: ToolStatuses = {
      heuristics: { status: "complete" },
      reputation: { status: "unavailable", reason_code: "provider_not_integrated" },
      llm: { status: "unavailable", reason_code: "opt_in_required" },
    };
    assert.equal(
      hasRuntimeCheckFailure(emailScanStatuses),
      false,
      "opt_in_required must NOT trigger hasRuntimeCheckFailure"
    );
  });

  it("Gemini opt-in disabled produces distinct advisory message, NOT crash/timeout phrasing", () => {
    const emailScanStatuses: ToolStatuses = {
      heuristics: { status: "complete" },
      reputation: { status: "unavailable", reason_code: "provider_not_integrated" },
      llm: { status: "unavailable", reason_code: "opt_in_required" },
    };
    const summary = getPartialAnalysisSummary([], emailScanStatuses);

    // Must NOT say the checks failed due to timeout/error
    assert.doesNotMatch(
      summary,
      /Some checks could not finish due to a service timeout or error/,
      "opt_in_required must not produce crash/timeout phrasing"
    );
    // Must clarify the opt-in state
    assert.match(
      summary,
      /opt-in required|opt-in|not.*integrated/i,
      "summary must explain the opt-in or unintegrated state"
    );
    // Must reinforce advisory nature
    assert.match(summary, /advisory|do not guarantee safety/i);
  });

  it("Gemini opt-in disabled alone (reputation complete) produces opt-in-specific message", () => {
    const statuses: ToolStatuses = {
      heuristics: { status: "complete" },
      reputation: { status: "complete" },
      llm: { status: "unavailable", reason_code: "opt_in_required" },
    };
    const summary = getPartialAnalysisSummary([], statuses);
    assert.match(summary, /opt-in required/i);
    assert.doesNotMatch(summary, /Some checks could not finish due to a service timeout/);
  });

  it("actual LLM timeout IS treated as runtime failure (distinguished from opt-in)", () => {
    const statuses: ToolStatuses = {
      heuristics: { status: "complete" },
      reputation: { status: "complete" },
      llm: { status: "timeout", reason_code: "request_timeout" },
    };
    assert.equal(hasRuntimeCheckFailure(statuses), true);
    const summary = getPartialAnalysisSummary([], statuses);
    assert.match(summary, /Some checks could not finish due to a service timeout or error/);
  });

  it("actual reputation error IS treated as runtime failure (distinguished from unintegrated)", () => {
    const statuses: ToolStatuses = {
      heuristics: { status: "complete" },
      reputation: { status: "error", reason_code: "upstream_503" },
      llm: { status: "complete" },
    };
    assert.equal(hasRuntimeCheckFailure(statuses), true);
    const summary = getPartialAnalysisSummary([], statuses);
    assert.match(summary, /Some checks could not finish due to a service timeout or error/);
  });

  it("reputation provider_not_integrated is NOT a runtime failure", () => {
    const statuses: ToolStatuses = {
      heuristics: { status: "complete" },
      reputation: { status: "unavailable", reason_code: "provider_not_integrated" },
      llm: { status: "complete" },
    };
    assert.equal(hasRuntimeCheckFailure(statuses), false);
    assert.equal(hasUnintegratedProvider(statuses), true);
  });

  it("both reputation unintegrated and Gemini opt-in disabled produce combined advisory", () => {
    const statuses: ToolStatuses = {
      heuristics: { status: "complete" },
      reputation: { status: "unavailable", reason_code: "provider_not_integrated" },
      llm: { status: "unavailable", reason_code: "opt_in_required" },
    };
    const summary = getPartialAnalysisSummary([], statuses);
    // Must mention both states
    assert.match(summary, /not yet integrated/i);
    assert.match(summary, /opt-in required/i);
    assert.doesNotMatch(summary, /Some checks could not finish due to a service timeout/);
  });

  it("produces clean no-indicators explanation when classification is null and no runtime failures occurred", () => {
    const statuses: ToolStatuses = {
      heuristics: { status: "complete" },
      reputation: { status: "unavailable", reason_code: "provider_not_integrated" },
      llm: { status: "unavailable", reason_code: "opt_in_required" },
    };
    const summaryEmail = getPartialAnalysisSummary(
      ["Deterministic heuristics completed without finding suspicious indicators."],
      statuses,
      null,
      "email"
    );
    assert.equal(
      summaryEmail,
      "No suspicious indicators detected by available checks. External AI and reputation checks were not performed. This does not establish that the email is safe."
    );

    const summaryWebsite = getPartialAnalysisSummary(
      [],
      statuses,
      null,
      "website"
    );
    assert.equal(
      summaryWebsite,
      "No suspicious indicators detected by available checks. External AI and reputation checks were not performed. This does not establish that the website is safe."
    );
  });

  it("runtime failure takes precedence over null classification", () => {
    const errorStatuses: ToolStatuses = {
      heuristics: { status: "complete" },
      reputation: { status: "unavailable", reason_code: "provider_not_integrated" },
      llm: { status: "error", reason_code: "http_500" },
    };
    const summary = getPartialAnalysisSummary(
      [],
      errorStatuses,
      null,
      "email"
    );
    assert.match(summary, /Some checks could not finish due to a service timeout or error/);
  });
});

describe("statusFormatting — getAdditionalFindings (Deduplication of Observed Signals vs Additional Findings)", () => {
  const sampleEvidence: EvidenceItem[] = [
    {
      type: "url_excessive_length",
      source: "heuristics",
      severity: "low",
      explanation: "5 links in this email exceed 100 characters in length (longest is 220 characters).",
    },
    {
      type: "deep_subdomain_nesting",
      source: "heuristics",
      severity: "low",
      explanation: "The hostname contains 3 or more subdomain levels, which is unusually deep.",
    },
  ];

  it("filters out any reason whose explanation is already displayed in Observed Signals", () => {
    const reasons = [
      "5 links in this email exceed 100 characters in length (longest is 220 characters).",
      "The hostname contains 3 or more subdomain levels, which is unusually deep.",
      "Reputation checking is not integrated, so this assessment does not include a reputation lookup.",
    ];

    const additional = getAdditionalFindings(reasons, sampleEvidence);

    // Explanations present in evidence must NOT appear in additional findings
    assert.equal(additional.length, 1);
    assert.equal(
      additional[0],
      "Reputation checking is not integrated, so this assessment does not include a reputation lookup."
    );
  });

  it("excludes index 0 even if it is not in evidence (preserves result summary prominence)", () => {
    const reasons = [
      "No suspicious indicators detected by available checks.",
      "Reputation checking is not integrated, so this assessment does not include a reputation lookup.",
      "External AI content analysis is disabled (opt-in required).",
    ];

    const additional = getAdditionalFindings(reasons, []);

    assert.equal(additional.length, 2);
    assert.equal(
      additional[0],
      "Reputation checking is not integrated, so this assessment does not include a reputation lookup."
    );
    assert.equal(
      additional[1],
      "External AI content analysis is disabled (opt-in required)."
    );
  });

  it("deduplicates identical reasons in additional findings", () => {
    const reasons = [
      "Primary summary reason",
      "Duplicate notice text",
      "Duplicate notice text",
      "Unique notice text",
    ];

    const additional = getAdditionalFindings(reasons, []);

    assert.deepEqual(additional, [
      "Duplicate notice text",
      "Unique notice text",
    ]);
  });

  it("handles empty reasons and undefined evidence safely", () => {
    assert.deepEqual(getAdditionalFindings([]), []);
    assert.deepEqual(getAdditionalFindings(["Sole reason"]), []);
  });
});
