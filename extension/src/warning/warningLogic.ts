/**
 * Production Warning Interstitial Business Logic & State Machines
 */

/**
 * Safely parse a URL query parameter value.
 */
export function getParam(params: URLSearchParams | null, key: string, fallback = ""): string {
  if (!params) return fallback;
  const raw = params.get(key);
  if (raw === null || raw === undefined) return fallback;
  return raw.trim();
}

/**
 * Normalize a hostname string for consistent comparisons.
 * Lowercases, trims whitespace, and strips trailing dots.
 */
export function normalizeHostname(host: string | null | undefined): string {
  if (!host || typeof host !== "string") return "";
  return host.trim().toLowerCase().replace(/\.+$/, "");
}

export type DestinationValidation =
  | { valid: true; url: string; hostname: string }
  | { valid: false; error: string };

/**
 * Validate the destination URL and verify that its hostname matches the expected domain.
 */
export function validateDestination(
  destUrlString: string | null | undefined,
  expectedDomain: string | null | undefined
): DestinationValidation {
  if (!destUrlString || typeof destUrlString !== "string" || !destUrlString.trim()) {
    return { valid: false, error: "No destination URL was provided. Navigation cancelled." };
  }

  let parsed: URL;
  try {
    parsed = new URL(destUrlString.trim());
  } catch {
    return { valid: false, error: "Destination URL is malformed. Navigation blocked for safety." };
  }

  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
    return {
      valid: false,
      error: `Unsafe destination scheme '${parsed.protocol}'. Only http: and https: are allowed.`,
    };
  }

  const destHost = normalizeHostname(parsed.hostname);
  const expectedHost = normalizeHostname(expectedDomain);

  if (!destHost || !expectedHost || destHost !== expectedHost) {
    return {
      valid: false,
      error: `Destination host mismatch (${destHost || "none"} vs ${expectedHost || "none"}). Navigation blocked.`,
    };
  }

  return { valid: true, url: parsed.href, hostname: destHost };
}

/**
 * Check if the document referrer matches or is a subdomain of the suspicious domain.
 */
export function isReferrerSuspicious(
  referrer: string | null | undefined,
  suspiciousDomain: string | null | undefined
): boolean {
  if (!referrer || typeof referrer !== "string" || !referrer.trim()) return false;
  let parsed: URL;
  try {
    parsed = new URL(referrer.trim());
  } catch {
    return false;
  }

  const refHost = normalizeHostname(parsed.hostname);
  const suspHost = normalizeHostname(suspiciousDomain);

  if (!refHost || !suspHost) return false;
  return refHost === suspHost || refHost.endsWith("." + suspHost);
}

export type SafeBackAction = "history_back" | "close_or_blank";

/**
 * Determine the safe back action strategy.
 */
export function determineSafeBackAction(
  historyLength: number,
  referrer: string | null | undefined,
  suspiciousDomain: string | null | undefined
): SafeBackAction {
  if (isReferrerSuspicious(referrer, suspiciousDomain)) {
    return "close_or_blank";
  }
  if (typeof historyLength === "number" && historyLength > 1) {
    return "history_back";
  }
  return "close_or_blank";
}

/**
 * Executes the safe back action using the provided environment objects.
 */
export function handleGoBack(
  historyObj: { length?: number; back?: () => void } | null | undefined,
  referrer: string | null | undefined,
  suspiciousDomain: string | null | undefined,
  windowObj: { close?: () => void; location?: { replace: (url: string) => void } } | null | undefined
): SafeBackAction {
  const length = historyObj && typeof historyObj.length === "number" ? historyObj.length : 1;
  const action = determineSafeBackAction(length, referrer, suspiciousDomain);

  if (action === "history_back" && historyObj && typeof historyObj.back === "function") {
    historyObj.back();
    return "history_back";
  }

  try {
    if (windowObj && typeof windowObj.close === "function") {
      windowObj.close();
    }
  } catch {
    // Ignore window.close() errors in sandboxed contexts
  }

  try {
    if (windowObj && windowObj.location && typeof windowObj.location.replace === "function") {
      windowObj.location.replace("about:blank");
    }
  } catch {
    // Ignore navigation errors
  }

  return "close_or_blank";
}

export interface ContinueState {
  armed: boolean;
  validation?: DestinationValidation;
}

export interface StepContinueResult {
  state: ContinueState;
  step: "armed" | "confirmed" | "error";
  error?: string;
}

/**
 * Pure state machine step for deliberate 2-step "Continue anyway" confirmation.
 */
export function stepContinueFlow(
  state: ContinueState,
  dest: string,
  domain: string
): StepContinueResult {
  if (!state || !state.armed) {
    const validation = validateDestination(dest, domain);
    if (!validation.valid) {
      return { state: { armed: false }, error: validation.error, step: "error" };
    }
    return {
      state: { armed: true, validation },
      step: "armed",
    };
  }

  return {
    state: { armed: false, validation: state.validation },
    step: "confirmed",
  };
}

/**
 * Persist an allowlist entry to session storage before navigation.
 */
export function recordSessionAllowlist(
  hostname: string,
  env: {
    chrome?: typeof chrome;
    sessionStorage?: Storage;
  } | null | undefined,
  callback: (err: Error | null) => void
): void {
  const normHost = normalizeHostname(hostname);
  if (!normHost) {
    callback(new Error("Invalid hostname for session allowlist"));
    return;
  }
  const allowlistKey = `allowlist_${normHost}`;
  const chromeObj = env && env.chrome !== undefined ? env.chrome : (typeof chrome !== "undefined" ? chrome : undefined);
  const sessionStorageObj =
    env && env.sessionStorage !== undefined ? env.sessionStorage : (typeof sessionStorage !== "undefined" ? sessionStorage : undefined);

  if (chromeObj && chromeObj.storage && chromeObj.storage.session && typeof chromeObj.storage.session.set === "function") {
    chromeObj.storage.session.set({ [allowlistKey]: true }, () => {
      const err = chromeObj.runtime && chromeObj.runtime.lastError;
      if (err) {
        callback(new Error(err.message || "Failed to save session allowlist"));
      } else {
        callback(null);
      }
    });
  } else if (sessionStorageObj && typeof sessionStorageObj.setItem === "function") {
    try {
      sessionStorageObj.setItem(allowlistKey, "true");
      callback(null);
    } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : "sessionStorage write failed";
      callback(new Error(msg));
    }
  } else {
    callback(new Error("No session storage provider available"));
  }
}
