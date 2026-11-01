/**
 * WARNING INTERSTITIAL CONTROLLER — Phishing Attack Detector
 * ===========================================================
 * Spike: extension/spikes/warning-interstitial/warning.js
 * Status: PROTOTYPE — not connected to production extension build.
 *
 * PURPOSE:
 *   Populates warning.html with detection metadata from URL query parameters,
 *   implements the "Go back to safety" history-back flow, and implements the
 *   "Continue anyway" session-allowlist flow.
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
 * SECURITY NOTES:
 *   - All query-parameter values are sanitized through textContent assignment
 *     (not innerHTML) to prevent XSS.
 *   - The destination URL for "Continue anyway" is validated to be http/https
 *     only before navigation to prevent javascript: / data: injection.
 *   - No API calls, no external network requests, no backend communication.
 *   - No credentials, page text, or email content is transmitted.
 *
 * REDIRECT LOOP PREVENTION:
 *   - "Continue anyway" stores the allowlisted domain in
 *     chrome.storage.session (session scope — cleared on browser/extension
 *     restart). The service worker checks this before intercepting.
 *   - If chrome.storage is unavailable (standalone file:// test), falls back
 *     to sessionStorage with a clearly logged warning.
 *   - A maximum of one automatic redirect is performed; if the destination
 *     URL still triggers the interstitial, the allowlist takes priority.
 *
 * MV3 ARCHITECTURE NOTES (documented for Spike Report):
 *   - This HTML file is registered as a web-accessible resource in manifest.json.
 *   - The service worker (background.js) intercepts high-risk navigations via
 *     chrome.webNavigation.onBeforeNavigate and redirects to:
 *       chrome-extension://<ID>/spikes/warning-interstitial/warning.html?domain=...
 *   - See SPIKE_REPORT.md for the full feasibility investigation.
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

  // 3. "Go back to safety" action
  document.getElementById('btn-back')?.addEventListener('click', function () {
    if (window.history && window.history.length > 1) {
      window.history.back();
    } else {
      try {
        window.location.replace('about:blank');
      } catch (e) {
        console.warn('[warning.js] Could not navigate to about:blank:', e.message);
      }
    }
  });

  // 4. "Continue anyway" action & destination validation
  const btnContinue = document.getElementById('btn-continue');
  btnContinue?.addEventListener('click', function () {
    // Disable immediately to prevent multiple clicks and race conditions
    btnContinue.disabled = true;

    const validation = validateDestination(dest, domain);
    if (!validation.valid) {
      // Re-enable button so retry is possible if action safely fails
      btnContinue.disabled = false;
      const confirmEl = document.getElementById('continue-confirm');
      if (confirmEl) {
        confirmEl.classList.add('visible');
        confirmEl.textContent = validation.error;
      }
      console.error('[warning.js] "Continue anyway" validation blocked:', validation.error);
      return;
    }

    // Validation succeeded — safe to proceed with allowlist
    const allowlistKey = `allowlist_${validation.hostname}`;

    function performNavigation() {
      window.location.replace(validation.url);
    }

    // Show the session-allowlist confirmation panel
    const confirmEl = document.getElementById('continue-confirm');
    if (confirmEl) {
      confirmEl.classList.add('visible');
      confirmEl.textContent = `Proceeding to ${validation.hostname}. This session allowlist entry will be cleared when the extension restarts.`;
    }

    if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.session) {
      chrome.storage.session.set({ [allowlistKey]: true }, function () {
        if (chrome.runtime && chrome.runtime.lastError) {
          console.warn('[warning.js] chrome.storage.session set error:', chrome.runtime.lastError.message);
        }
        performNavigation();
      });
    } else {
      console.warn(
        '[warning.js] chrome.storage.session not available. ' +
        'Using sessionStorage as fallback (spike testing only — not for production).'
      );
      try {
        sessionStorage.setItem(allowlistKey, 'true');
      } catch (e) {
        console.warn('[warning.js] sessionStorage also unavailable:', e.message);
      }
      setTimeout(performNavigation, 1200);
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
  };
}
