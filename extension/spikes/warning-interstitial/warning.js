/**
 * WARNING INTERSTITIAL CONTROLLER — Phishing Attack Detector
 * ===========================================================
 * Spike: extension/spikes/warning-interstitial/warning.js
 * Status: PROTOTYPE — not connected to production extension build.
 *
 * PURPOSE:
 *   Populates warning.html with detection metadata from URL query parameters,
 *   implements the "Go back to safety" history-back flow, and implements the
 *   deliberate 2-step "Continue anyway" session-allowlist flow.
 *
 * QUERY PARAMETER CONTRACT:
 *   ?domain=   Destination hostname (URL-decoded). Required.
 *   ?score=    Risk score integer 0–100. Optional; defaults to "—".
 *   ?reason1=  First reason (URL-decoded). Optional.
 *   ?reason2=  Second reason (URL-decoded). Optional.
 *   ?reason3=  Third reason (URL-decoded). Optional.
 *   ?dest=     Full destination URL (URL-encoded). Required for "Continue anyway".
 *   ?partial=  "1" if analysis was partial or incomplete. Optional.
 *
 * SECURITY CONTROLS:
 *   - All query-parameter values are sanitized through textContent assignment
 *     (not innerHTML) to prevent XSS.
 *   - "Continue anyway" enforces a deliberate 2-step confirmation ("Arm & Confirm")
 *     requiring the user to review the warning before navigation occurs.
 *   - "Go back to safety" validates the referrer: if the referrer matches the
 *     suspicious domain, history.back() is aborted to prevent returning directly
 *     to the phishing site; a neutral fallback (window.close or about:blank) is used.
 *   - The destination URL for "Continue anyway" is validated to be http/https
 *     only before navigation to prevent javascript: / data: injection.
 *   - No external network requests or credential transmission.
 */

'use strict';

// ---------------------------------------------------------------------------
// 1. URL parameter & validation helper functions
// ---------------------------------------------------------------------------

/**
 * Safely parse a URL query parameter value.
 *
 * @param {URLSearchParams} params
 * @param {string} key
 * @param {string} [fallback='']
 * @returns {string}
 */
function getParam(params, key, fallback = '') {
  if (!params) return fallback;
  const raw = params.get(key);
  if (raw === null || raw === undefined) return fallback;
  return raw.trim();
}

/**
 * Normalize a hostname string for consistent comparisons.
 * Lowercases, trims whitespace, and strips trailing dots.
 *
 * @param {string} host
 * @returns {string}
 */
function normalizeHostname(host) {
  if (!host || typeof host !== 'string') return '';
  return host.trim().toLowerCase().replace(/\.+$/, '');
}

/**
 * Validate the destination URL and verify that its hostname matches the expected domain.
 *
 * Policy:
 * - Requires a valid, non-empty URL string with protocol 'http:' or 'https:'.
 * - Destination hostname and expected warning domain must match after normalization.
 *
 * @param {string} destUrlString
 * @param {string} expectedDomain
 * @returns {{ valid: true, url: string, hostname: string } | { valid: false, error: string }}
 */
function validateDestination(destUrlString, expectedDomain) {
  if (!destUrlString || typeof destUrlString !== 'string' || !destUrlString.trim()) {
    return { valid: false, error: 'No destination URL was provided. Navigation cancelled.' };
  }

  let parsed;
  try {
    parsed = new URL(destUrlString.trim());
  } catch (_) {
    return { valid: false, error: 'Destination URL is malformed. Navigation blocked for safety.' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return { valid: false, error: `Unsafe destination scheme '${parsed.protocol}'. Only http: and https: are allowed.` };
  }

  const destHost = normalizeHostname(parsed.hostname);
  const expectedHost = normalizeHostname(expectedDomain);

  if (!destHost || !expectedHost || destHost !== expectedHost) {
    return {
      valid: false,
      error: `Destination host mismatch (${destHost || 'none'} vs ${expectedHost || 'none'}). Navigation blocked.`,
    };
  }

  return { valid: true, url: parsed.href, hostname: destHost };
}

/**
 * Check if the document referrer matches or is a subdomain of the suspicious domain.
 * If the referrer is suspicious, calling history.back() would navigate the user right
 * back into the malicious site that triggered the interstitial.
 *
 * @param {string} referrer
 * @param {string} suspiciousDomain
 * @returns {boolean}
 */
function isReferrerSuspicious(referrer, suspiciousDomain) {
  if (!referrer || typeof referrer !== 'string' || !referrer.trim()) return false;
  let parsed;
  try {
    parsed = new URL(referrer.trim());
  } catch (_) {
    return false;
  }

  const refHost = normalizeHostname(parsed.hostname);
  const suspHost = normalizeHostname(suspiciousDomain);

  if (!refHost || !suspHost) return false;
  return refHost === suspHost || refHost.endsWith('.' + suspHost);
}

/**
 * Determine the safe back action strategy.
 *
 * Policy:
 * 1. If referrer is suspicious (matches the warning domain), DO NOT go back in history;
 *    return 'close_or_blank' to avoid returning to the phishing site.
 * 2. If history.length > 1 and referrer is safe, return 'history_back'.
 * 3. Otherwise (history.length <= 1), return 'close_or_blank'.
 *
 * @param {number} historyLength
 * @param {string} referrer
 * @param {string} suspiciousDomain
 * @returns {'history_back' | 'close_or_blank'}
 */
function determineSafeBackAction(historyLength, referrer, suspiciousDomain) {
  if (isReferrerSuspicious(referrer, suspiciousDomain)) {
    return 'close_or_blank';
  }
  if (typeof historyLength === 'number' && historyLength > 1) {
    return 'history_back';
  }
  return 'close_or_blank';
}

/**
 * Executes the safe back action using the provided environment objects.
 *
 * @param {object} historyObj - e.g. window.history
 * @param {string} referrer - e.g. document.referrer
 * @param {string} suspiciousDomain - e.g. target domain parameter
 * @param {object} windowObj - e.g. window
 * @returns {'history_back' | 'close_or_blank'}
 */
function handleGoBack(historyObj, referrer, suspiciousDomain, windowObj) {
  const length = (historyObj && typeof historyObj.length === 'number') ? historyObj.length : 1;
  const action = determineSafeBackAction(length, referrer, suspiciousDomain);

  if (action === 'history_back' && historyObj && typeof historyObj.back === 'function') {
    historyObj.back();
    return 'history_back';
  }

  // Fallback: try closing the tab (safe exit), then replace location with about:blank
  try {
    if (windowObj && typeof windowObj.close === 'function') {
      windowObj.close();
    }
  } catch (_) {}

  try {
    if (windowObj && windowObj.location && typeof windowObj.location.replace === 'function') {
      windowObj.location.replace('about:blank');
    }
  } catch (_) {}

  return 'close_or_blank';
}

/**
 * Pure state machine step for deliberate 2-step "Continue anyway" confirmation.
 *
 * @param {{ armed: boolean, validation?: object }} state
 * @param {string} dest
 * @param {string} domain
 * @returns {{ state: { armed: boolean, validation?: object }, error?: string, step: 'armed' | 'confirmed' | 'error' }}
 */
function stepContinueFlow(state, dest, domain) {
  if (!state || !state.armed) {
    const validation = validateDestination(dest, domain);
    if (!validation.valid) {
      return { state: { armed: false }, error: validation.error, step: 'error' };
    }
    return {
      state: { armed: true, validation },
      step: 'armed',
    };
  }

  // Already armed — user clicked deliberate confirmation
  return {
    state: { armed: false, validation: state.validation },
    step: 'confirmed',
  };
}

/**
 * Persist an allowlist entry to session storage before navigation.
 *
 * Policy:
 * - If chrome.storage.session is available:
 *   Calls chrome.storage.session.set({ [allowlistKey]: true }, callback).
 *   Checks chrome.runtime.lastError. If lastError exists, invokes callback(new Error(lastError.message)).
 *   If successful, invokes callback(null).
 * - Else (standalone fallback):
 *   Writes allowlistKey to sessionStorage.
 *   If it throws or fails, invokes callback(error).
 *   If successful, invokes callback(null).
 *
 * @param {string} hostname
 * @param {object} [env]
 * @param {object} [env.chrome]
 * @param {object} [env.sessionStorage]
 * @param {function(Error|null): void} callback
 */
function recordSessionAllowlist(hostname, env, callback) {
  const normHost = normalizeHostname(hostname);
  if (!normHost) {
    callback(new Error('Invalid hostname for session allowlist'));
    return;
  }
  const allowlistKey = `allowlist_${normHost}`;
  const chromeObj = (env && env.chrome !== undefined) ? env.chrome : (typeof chrome !== 'undefined' ? chrome : undefined);
  const sessionStorageObj = (env && env.sessionStorage !== undefined) ? env.sessionStorage : (typeof sessionStorage !== 'undefined' ? sessionStorage : undefined);

  if (chromeObj && chromeObj.storage && chromeObj.storage.session && typeof chromeObj.storage.session.set === 'function') {
    chromeObj.storage.session.set({ [allowlistKey]: true }, function () {
      const err = chromeObj.runtime && chromeObj.runtime.lastError;
      if (err) {
        callback(new Error(err.message || 'Failed to save session allowlist'));
      } else {
        callback(null);
      }
    });
  } else if (sessionStorageObj && typeof sessionStorageObj.setItem === 'function') {
    try {
      sessionStorageObj.setItem(allowlistKey, 'true');
      callback(null);
    } catch (e) {
      callback(new Error(e.message || 'sessionStorage write failed'));
    }
  } else {
    callback(new Error('No session storage provider available'));
  }
}

// ---------------------------------------------------------------------------
// 2. Browser DOM & Event Initialization (guarded for Node.js / test harnesses)
// ---------------------------------------------------------------------------

if (typeof window !== 'undefined' && typeof document !== 'undefined') {
  const searchString = window.location ? window.location.search : '';
  const params = new URLSearchParams(searchString);

  const domain    = getParam(params, 'domain', 'Unknown destination');
  const rawScore  = getParam(params, 'score', '');
  const dest      = getParam(params, 'dest', '');
  const isPartial = getParam(params, 'partial', '0') === '1';

  const reasons = [
    getParam(params, 'reason1', ''),
    getParam(params, 'reason2', ''),
    getParam(params, 'reason3', ''),
  ].filter(r => r.length > 0);

  function setText(id, text) {
    const el = document.getElementById(id);
    if (el) el.textContent = text;
  }

  // Domain — used in multiple places
  setText('destination-domain', domain);
  setText('confirm-domain', domain);

  // Risk score — validate it is a reasonable integer before display
  const scoreInt = parseInt(rawScore, 10);
  if (!isNaN(scoreInt) && scoreInt >= 0 && scoreInt <= 100) {
    setText('risk-score', String(scoreInt));
    const scoreEl = document.getElementById('risk-score');
    if (scoreEl) scoreEl.setAttribute('aria-label', `Risk score: ${scoreInt} out of 100`);
  } else {
    setText('risk-score', '—');
  }

  // Reasons list
  const reasonsList = document.getElementById('reasons-list');
  if (reasonsList) {
    if (reasons.length === 0) {
      const li = document.createElement('li');
      li.className = 'reason-item';
      const dot = document.createElement('span');
      dot.className = 'reason-dot';
      dot.setAttribute('aria-hidden', 'true');
      const text = document.createElement('span');
      text.textContent = 'Multiple phishing indicators were detected by the analysis.';
      li.appendChild(dot);
      li.appendChild(text);
      reasonsList.appendChild(li);
    } else {
      reasons.forEach(reason => {
        const li = document.createElement('li');
        li.className = 'reason-item';
        const dot = document.createElement('span');
        dot.className = 'reason-dot';
        dot.setAttribute('aria-hidden', 'true');
        const text = document.createElement('span');
        text.textContent = reason;  // textContent — XSS-safe
        li.appendChild(dot);
        li.appendChild(text);
        reasonsList.appendChild(li);
      });
    }
  }

  // Partial analysis notice
  if (isPartial) {
    const notice = document.getElementById('partial-notice');
    if (notice) notice.hidden = false;
  }

  // 3. "Go back to safety" action — guarded against redirect loops
  document.getElementById('btn-back')?.addEventListener('click', function () {
    handleGoBack(
      window.history,
      document.referrer || '',
      domain,
      window
    );
  });

  // 4. "Continue anyway" action with deliberate 2-step confirmation
  let continueState = { armed: false };
  const btnContinue = document.getElementById('btn-continue');
  const confirmEl = document.getElementById('continue-confirm');

  btnContinue?.addEventListener('click', function () {
    const stepResult = stepContinueFlow(continueState, dest, domain);
    continueState = stepResult.state;

    if (stepResult.step === 'error') {
      if (confirmEl) {
        confirmEl.classList.add('visible');
        confirmEl.textContent = stepResult.error || 'Destination URL validation failed.';
      }
      console.error('[warning.js] "Continue anyway" validation blocked:', stepResult.error);
      return;
    }

    if (stepResult.step === 'armed') {
      // Step 1: Arm the confirmation state — do not navigate or allowlist yet
      if (confirmEl) {
        confirmEl.classList.add('visible');
        confirmEl.textContent =
          `Warning: Proceeding to ${stepResult.state.validation.hostname} will bypass phishing warnings ` +
          `for this site during this browser session. If you are certain this destination is safe, click below to confirm.`;
      }
      btnContinue.textContent = 'Confirm and proceed to site';
      btnContinue.classList.add('btn-confirm-active');
      btnContinue.setAttribute(
        'aria-label',
        `Confirm and proceed to ${stepResult.state.validation.hostname} at your own risk`
      );
      return;
    }

    if (stepResult.step === 'confirmed') {
      // Step 2: Deliberate confirmation received — proceed to allowlist and navigate
      btnContinue.disabled = true;
      const targetHost = stepResult.state.validation.hostname;
      const targetUrl = stepResult.state.validation.url;

      if (confirmEl) {
        confirmEl.textContent = `Saving session allowlist for ${targetHost}...`;
      }

      function performNavigation() {
        window.location.replace(targetUrl);
      }

      recordSessionAllowlist(targetHost, null, function (err) {
        if (err) {
          // Allowlist failed — keep warning page active and do not navigate
          btnContinue.disabled = false;
          btnContinue.textContent = 'Retry allowlist & continue';
          if (confirmEl) {
            confirmEl.classList.add('visible');
            confirmEl.textContent = `Allowlist storage failed: ${err.message}. Navigation blocked for safety.`;
          }
          console.error('[warning.js] Session allowlist error:', err.message);
          return;
        }

        if (confirmEl) {
          confirmEl.textContent = `Proceeding to ${targetHost}...`;
        }
        performNavigation();
      });
    }
  });

  // 5. Keyboard accessibility — Escape key goes back to safety
  document.addEventListener('keydown', function (event) {
    if (event.key === 'Escape') {
      document.getElementById('btn-back')?.click();
    }
  });

  // 6. Initial focus — set to primary action button
  window.addEventListener('DOMContentLoaded', function () {
    const backBtn = document.getElementById('btn-back');
    if (backBtn) {
      backBtn.focus({ preventScroll: false });
    }
  });
}

// Node.js test harness export
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    getParam,
    normalizeHostname,
    validateDestination,
    isReferrerSuspicious,
    determineSafeBackAction,
    handleGoBack,
    stepContinueFlow,
    recordSessionAllowlist,
  };
}
