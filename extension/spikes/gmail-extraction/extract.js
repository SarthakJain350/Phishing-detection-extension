/**
 * GMAIL DOM EXTRACTION PROTOTYPE — Phishing Attack Detector
 * ===========================================================
 * Spike: extension/spikes/gmail-extraction/extract.js
 * Status: PROTOTYPE — not connected to production extension build.
 * Author: Rohan (Phase 2, Task 2.3.2)
 *
 * PURPOSE:
 *   Feasibility spike for extracting structured metadata from an open Gmail
 *   message thread using DOM selectors. This script is intended to run as a
 *   Chrome extension content script on https://mail.google.com/* when the
 *   user explicitly triggers a scan action.
 *
 * PRIVACY GUARDRAILS (must be preserved in production wiring):
 *   - This module ONLY extracts and returns data in-memory.
 *   - It does NOT send any data to the backend, any external service, or
 *     any extension background script without an explicit user action.
 *   - Body text is hard-truncated at BODY_MAX_CHARS (3,000 chars).
 *   - Links are capped at LINK_MAX_COUNT (10 links).
 *   - Sender is extracted as domain/address only — no attempt to extract
 *     personal identifiers beyond what Gmail's own UI displays.
 *   - Subject is truncated at SUBJECT_MAX_CHARS (256 chars).
 *   - console.log/warn calls in this file must NEVER log extracted email
 *     content, URLs, or sender addresses (only status codes and selector names).
 *
 * SELECTOR FRAGILITY WARNING:
 *   Gmail's DOM selectors are undocumented and frequently change across
 *   deployments. All selectors in this file are empirically observed as of
 *   2026 and must be treated as best-effort approximations. See SPIKE_REPORT.md
 *   for the full fragility analysis and recommended fallback strategies.
 *
 * USAGE (content-script context or browser console on mail.google.com):
 *   const result = extractGmailMessage();
 *   if (result.success) {
 *     // Send result to background via chrome.runtime.sendMessage
 *   } else {
 *     console.log('[extract.js] Extraction failed:', result.reason);
 *   }
 *
 * RETURN VALUE:
 *   On success: {
 *     success: true,
 *     subject:  string,   // max 256 chars, empty string if not found
 *     sender:   string,   // email address or display name from UI, empty if not found
 *     bodyText: string,   // max 3000 chars, empty string if not found
 *     links:    string[], // max 10 http/https URLs from message body
 *   }
 *   On failure: {
 *     success: false,
 *     reason:  string,    // machine-readable reason code
 *   }
 */

'use strict';

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Maximum body text length sent for analysis. Enforced by the backend schema. */
const BODY_MAX_CHARS = 3000;

/** Maximum links extracted from message body. Enforced by the backend schema. */
const LINK_MAX_COUNT = 10;

/** Maximum subject line length. Enforced by the backend schema. */
const SUBJECT_MAX_CHARS = 256;

/** Maximum link URL length accepted by backend. Enforced by EmailScanRequest schema. */
const URL_MAX_CHARS = 2048;

/**
 * Ordered list of CSS selectors for the message subject.
 * Tried in order; the first non-empty match is used.
 *
 * FRAGILITY NOTE: These selectors are empirically observed and may break
 * on Gmail DOM updates. See SPIKE_REPORT.md §2.2 for fallback strategy.
 */
const SUBJECT_SELECTORS = [
  '.hP',             // Primary: open message subject span (desktop Gmail)
  'h2.ha',           // Alt: some Gmail versions use h2 with class "ha"
  '[data-thread-id] .hP',  // Thread-wrapped context
];

/**
 * Ordered list of CSS selectors for the sender email/name element.
 * Gmail surfaces the email address in the .gD element's `email` attribute
 * or inner text depending on viewport state (full address vs. display name).
 */
const SENDER_SELECTORS = [
  '.gD',             // Primary: sender address span (desktop Gmail)
  '.go[email]',      // Alternative: sender in compact header
  '.yP[email]',      // Alternative: another known variant
];

/**
 * Ordered list of CSS selectors for the message body text container.
 * The body text is the human-readable plain text portion of the email.
 */
const BODY_SELECTORS = [
  '.a3s.aiL',        // Primary: Gmail message body container
  '.a3s',            // Fallback: body without the aiL modifier
  '.ii.gt .a3s',     // Legacy fallback: full thread context
];

// ---------------------------------------------------------------------------
// Helper utilities
// ---------------------------------------------------------------------------

/**
 * Try each selector in order and return the first Element match.
 * Returns null if no selector matches.
 *
 * @param {string[]} selectors
 * @param {Document|Element} [root=document]
 * @returns {Element|null}
 */
function trySelectors(selectors, root = document) {
  for (const selector of selectors) {
    try {
      const el = root.querySelector(selector);
      if (el) return el;
    } catch (e) {
      // Selector syntax error — skip to next candidate
      console.warn('[extract.js] Selector error for "' + selector + '":', e.message);
    }
  }
  return null;
}

/**
 * Safely extract text content from an element, trimmed and bounded.
 *
 * @param {Element|null} el
 * @param {number} maxLength
 * @returns {string}
 */
function safeText(el, maxLength) {
  if (!el) return '';
  const text = (el.textContent || '').trim();
  return text.slice(0, maxLength);
}

/**
 * Derive the sender string from a Gmail sender element.
 * Gmail stores the email address in the `email` attribute when the display
 * name and email differ. Falls back to textContent.
 *
 * @param {Element|null} el
 * @returns {string}
 */
function extractSender(el) {
  if (!el) return '';
  // Prefer the `email` attribute (actual email address) over display name
  const emailAttr = el.getAttribute('email') || '';
  if (emailAttr.trim()) return emailAttr.trim().slice(0, 256);
  // Fall back to textContent (may be a display name like "PayPal")
  return safeText(el, 256);
}

/**
 * Check if a hostname safely belongs to Google (e.g. google.com, www.google.com,
 * google.co.uk), rejecting deceptive lookalikes such as evilgoogle.com or google.evil.com.
 *
 * @param {string} hostname
 * @returns {boolean}
 */
function isGoogleHost(hostname) {
  if (!hostname || typeof hostname !== 'string') return false;
  const host = hostname.toLowerCase().trim().replace(/\.+$/, '');
  if (host === 'google.com' || host.endsWith('.google.com')) {
    return true;
  }
  // Match international ccTLD variants (e.g. google.co.uk, www.google.ca, google.de)
  // Host must be exactly google.<tld> or a subdomain ending in .google.<tld>
  return /^(?:[a-z0-9-]+\.)*google\.(?:[a-z]{2,3}|co\.[a-z]{2}|com\.[a-z]{2})$/i.test(host);
}

/**
 * Resolve an anchor href to an absolute target link, unwrapping recognized Google
 * /url redirect wrappers and enforcing valid http/https scheme and the 2,048-char cap.
 *
 * @param {string} rawHref
 * @param {string} [baseHref=window.location.href]
 * @returns {string|null} Resolved valid URL, or null if invalid, unsafe, or exceeds limit.
 */
function resolveLinkUrl(rawHref, baseHref) {
  if (!rawHref || typeof rawHref !== 'string') return null;
  const trimmed = rawHref.trim();
  if (!trimmed) return null;

  let parsed;
  try {
    parsed = new URL(trimmed, baseHref || 'https://mail.google.com');
  } catch (_) {
    return null;
  }

  // Handle recognized Google redirect wrappers (e.g. https://www.google.com/url?q=https://target.com&...)
  if (isGoogleHost(parsed.hostname) && parsed.pathname.toLowerCase() === '/url') {
    const q = parsed.searchParams.get('q');
    if (q) {
      try {
        const unwrapped = new URL(q.trim());
        if (unwrapped.protocol === 'http:' || unwrapped.protocol === 'https:') {
          if (unwrapped.href.length > URL_MAX_CHARS) {
            return null; // Discard links exceeding 2,048 chars (do not truncate)
          }
          return unwrapped.href;
        }
        // Unsafe scheme in redirect target (e.g. javascript:, data:) — drop
        return null;
      } catch (_) {
        // Malformed q parameter — drop
        return null;
      }
    }
  }

  // Ordinary link (or non-wrapper Google link): accept http and https only
  if (parsed.protocol === 'http:' || parsed.protocol === 'https:') {
    if (parsed.href.length > URL_MAX_CHARS) {
      return null; // Discard links exceeding 2,048 chars (do not truncate)
    }
    return parsed.href;
  }

  return null;
}

/**
 * Extract up to LINK_MAX_COUNT valid http/https URLs from a body element.
 * Filters out mailto:, javascript:, anchor-only (#), and oversize links.
 * Automatically unwraps recognized Google /url redirect wrappers.
 *
 * @param {Element|null} bodyEl
 * @returns {string[]}
 */
function extractLinks(bodyEl) {
  if (!bodyEl) return [];

  const anchors = Array.from(bodyEl.querySelectorAll('a[href]'));
  const links = [];

  for (const anchor of anchors) {
    if (links.length >= LINK_MAX_COUNT) break;

    const href = anchor.getAttribute('href');
    const resolved = resolveLinkUrl(href, window.location.href);
    if (resolved) {
      links.push(resolved);
    }
  }

  return links;
}

/**
 * Detect whether an open Gmail message thread is currently visible.
 * This checks for the presence of the message body container, which is
 * absent when the user is viewing the inbox list or a collapsed thread.
 *
 * @returns {boolean}
 */
function isMessageOpen() {
  // A message is considered "open" only if at least one body container exists
  // AND is not empty (expanded thread has at least one readable message).
  for (const selector of BODY_SELECTORS) {
    try {
      const el = document.querySelector(selector);
      if (el && (el.textContent || '').trim().length > 0) return true;
    } catch (_) {
      // Ignore selector errors
    }
  }
  return false;
}

// ---------------------------------------------------------------------------
// Main extraction function
// ---------------------------------------------------------------------------

/**
 * Extract metadata from the currently open Gmail message thread.
 *
 * This function is the primary export. It is called by the content script's
 * message listener when the user triggers a scan via the extension popup
 * or inline Gmail panel.
 *
 * @returns {{ success: true, subject: string, sender: string, bodyText: string, links: string[] }
 *          | { success: false, reason: string }}
 */
function extractGmailMessage() {
  // ---- Guard 1: Verify we are on mail.google.com -------------------------
  if (!window.location.hostname.includes('mail.google.com')) {
    return {
      success: false,
      reason: 'not_on_gmail',
    };
  }

  // ---- Guard 2: Verify an email thread is open ---------------------------
  if (!isMessageOpen()) {
    return {
      success: false,
      reason: 'no_open_message',
    };
  }

  // ---- Extract subject ----------------------------------------------------
  const subjectEl = trySelectors(SUBJECT_SELECTORS);
  const subject = safeText(subjectEl, SUBJECT_MAX_CHARS);
  // Note: subject may be empty if the selector didn't match — not a failure

  // ---- Extract sender -----------------------------------------------------
  const senderEl = trySelectors(SENDER_SELECTORS);
  const sender = extractSender(senderEl);
  // Note: sender may be empty — not treated as a hard failure

  // ---- Extract body text --------------------------------------------------
  const bodyEl = trySelectors(BODY_SELECTORS);
  const bodyText = safeText(bodyEl, BODY_MAX_CHARS);

  // ---- Hard failure: no readable body text --------------------------------
  // If we detected an open message (isMessageOpen passed) but can't read
  // body text at all, report a partial failure rather than fabricating data.
  if (!bodyEl || bodyText.length === 0) {
    return {
      success: false,
      reason: 'body_extraction_failed',
    };
  }

  // ---- Extract links ------------------------------------------------------
  const links = extractLinks(bodyEl);

  // ---- Success ------------------------------------------------------------
  return {
    success: true,
    subject,    // string, possibly empty if not found
    sender,     // string, possibly empty if not found
    bodyText,   // string, max BODY_MAX_CHARS chars
    links,      // string[], max LINK_MAX_COUNT items, http/https only
  };
}

// ---------------------------------------------------------------------------
// Content script message listener (MV3 wiring — disconnected in spike)
// ---------------------------------------------------------------------------

/**
 * In production, the content script listens for messages from the service
 * worker / popup requesting extraction. This is the canonical message handler.
 *
 * In this spike, the listener is registered but the background messaging
 * infrastructure is not wired to the production extension.
 *
 * Example production usage in background.js / popup.js:
 *   chrome.tabs.sendMessage(tabId, { type: 'EXTRACT_GMAIL' }, (response) => {
 *     if (response?.success) { ... }
 *   });
 */
if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.onMessage) {
  chrome.runtime.onMessage.addListener(function (message, sender, sendResponse) {
    if (message && message.type === 'EXTRACT_GMAIL') {
      const result = extractGmailMessage();
      // PRIVACY NOTE: result.bodyText and result.links are user email data.
      // Only send to background if the user explicitly triggered the scan.
      sendResponse(result);
      return true; // Keep the message channel open for async response
    }
  });
}

// ---------------------------------------------------------------------------
// Standalone testing export (browser console / test harness)
// ---------------------------------------------------------------------------

/**
 * When running in a browser console or test harness (not as a Chrome extension
 * content script), export the function via window for manual testing.
 *
 * Manual test steps (see SPIKE_REPORT.md §4):
 *   1. Open Gmail in Chrome and navigate to an email.
 *   2. Open DevTools → Console.
 *   3. Paste the contents of this file into the console (or load via snippet).
 *   4. Run: extractGmailMessage()
 *   5. Verify the returned object matches the documented schema.
 */
if (typeof window !== 'undefined') {
  window.extractGmailMessage = extractGmailMessage;
}

// Node.js/test-harness export (for unit testing without a browser DOM)
if (typeof module !== 'undefined' && module.exports) {
  module.exports = {
    extractGmailMessage,
    // Export internals for unit testing
    isMessageOpen,
    extractLinks,
    extractSender,
    safeText,
    trySelectors,
    isGoogleHost,
    resolveLinkUrl,
    BODY_MAX_CHARS,
    LINK_MAX_COUNT,
    SUBJECT_MAX_CHARS,
    URL_MAX_CHARS,
  };
}
