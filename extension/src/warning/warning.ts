/**
 * Production Warning Interstitial Controller
 */

import {
  getParam,
  handleGoBack,
  stepContinueFlow,
  recordSessionAllowlist,
  type ContinueState,
} from "./warningLogic";

function initWarningPage(): void {
  const searchString = typeof window !== "undefined" && window.location ? window.location.search : "";
  const params = new URLSearchParams(searchString);

  const domain = getParam(params, "domain", "Unknown destination");
  const rawScore = getParam(params, "score", "");
  const dest = getParam(params, "dest", "");
  const isPartial = getParam(params, "partial", "0") === "1";

  const reasons = [
    getParam(params, "reason1", ""),
    getParam(params, "reason2", ""),
    getParam(params, "reason3", ""),
  ].filter((r) => r.length > 0);

  function setText(id: string, text: string): void {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  setText("destination-domain", domain);
  setText("confirm-domain", domain);

  const scoreInt = parseInt(rawScore, 10);
  if (!isNaN(scoreInt) && scoreInt >= 0 && scoreInt <= 100) {
    setText("risk-score", String(scoreInt));
    const scoreEl = document.getElementById("risk-score");
    if (scoreEl) scoreEl.setAttribute("aria-label", `Risk score: ${scoreInt} out of 100`);
  } else {
    setText("risk-score", "—");
  }

  const reasonsList = document.getElementById("reasons-list");
  if (reasonsList) {
    if (reasons.length === 0) {
      const li = document.createElement("li");
      li.className = "reason-item";
      const dot = document.createElement("span");
      dot.className = "reason-dot";
      dot.setAttribute("aria-hidden", "true");
      const text = document.createElement("span");
      text.textContent = "Multiple phishing indicators were detected by the analysis.";
      li.appendChild(dot);
      li.appendChild(text);
      reasonsList.appendChild(li);
    } else {
      reasons.forEach((reason) => {
        const li = document.createElement("li");
        li.className = "reason-item";
        const dot = document.createElement("span");
        dot.className = "reason-dot";
        dot.setAttribute("aria-hidden", "true");
        const text = document.createElement("span");
        text.textContent = reason;
        li.appendChild(dot);
        li.appendChild(text);
        reasonsList.appendChild(li);
      });
    }
  }

  if (isPartial) {
    const notice = document.getElementById("partial-notice");
    if (notice) notice.hidden = false;
  }

  // Go back to safety action
  document.getElementById("btn-back")?.addEventListener("click", () => {
    handleGoBack(
      window.history,
      document.referrer || "",
      domain,
      window
    );
  });

  // Continue anyway action with 2-step deliberate confirmation
  let continueState: ContinueState = { armed: false };
  const btnContinue = document.getElementById("btn-continue") as HTMLButtonElement | null;
  const confirmEl = document.getElementById("continue-confirm");

  btnContinue?.addEventListener("click", () => {
    const stepResult = stepContinueFlow(continueState, dest, domain);
    continueState = stepResult.state;

    if (stepResult.step === "error") {
      if (confirmEl) {
        confirmEl.classList.add("visible");
        confirmEl.textContent = stepResult.error || "Destination URL validation failed.";
      }
      return;
    }

    if (stepResult.step === "armed" && stepResult.state.validation && stepResult.state.validation.valid) {
      if (confirmEl) {
        confirmEl.classList.add("visible");
        confirmEl.textContent =
          `Warning: Proceeding to ${stepResult.state.validation.hostname} will bypass phishing warnings ` +
          `for this site during this browser session. If you are certain this destination is safe, click below to confirm.`;
      }
      btnContinue.textContent = "Confirm and proceed to site";
      btnContinue.classList.add("btn-confirm-active");
      btnContinue.setAttribute(
        "aria-label",
        `Confirm and proceed to ${stepResult.state.validation.hostname} at your own risk`
      );
      return;
    }

    if (stepResult.step === "confirmed" && stepResult.state.validation && stepResult.state.validation.valid) {
      btnContinue.disabled = true;
      const targetHost = stepResult.state.validation.hostname;
      const targetUrl = stepResult.state.validation.url;

      if (confirmEl) {
        confirmEl.textContent = `Saving session allowlist for ${targetHost}...`;
      }

      function performNavigation(): void {
        window.location.replace(targetUrl);
      }

      recordSessionAllowlist(targetHost, null, (err) => {
        if (err) {
          btnContinue.disabled = false;
          btnContinue.textContent = "Retry allowlist & continue";
          if (confirmEl) {
            confirmEl.classList.add("visible");
            confirmEl.textContent = `Allowlist storage failed: ${err.message}. Navigation blocked for safety.`;
          }
          return;
        }

        if (confirmEl) {
          confirmEl.textContent = `Proceeding to ${targetHost}...`;
        }
        performNavigation();
      });
    }
  });

  document.addEventListener("keydown", (event) => {
    if (event.key === "Escape") {
      document.getElementById("btn-back")?.click();
    }
  });

  const backBtn = document.getElementById("btn-back");
  if (backBtn) {
    backBtn.focus({ preventScroll: false });
  }
}

if (typeof document !== "undefined") {
  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", initWarningPage);
  } else {
    initWarningPage();
  }
}
