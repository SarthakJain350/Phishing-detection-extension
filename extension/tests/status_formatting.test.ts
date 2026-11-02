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
  getPartialAnalysisSummary,
} from "../src/popup/statusFormatting.ts";

import type { ToolStatuses } from "../src/popup/types.ts";

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
