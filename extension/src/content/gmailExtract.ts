// Gmail content script for Phishing Attack Detector
// This script extracts email metadata from Gmail UI and communicates via chrome.runtime messages.
// It mirrors the prototype logic in spikes/gmail-extraction/extract.js with TypeScript typings.

'use strict';

// Constants matching backend constraints
const BODY_MAX_CHARS = 3000;
const LINK_MAX_COUNT = 10;
const SUBJECT_MAX_CHARS = 256;
const URL_MAX_CHARS = 2048;

// Selectors (same as prototype)
const SUBJECT_SELECTORS = [
  '.hP',
  'h2.ha',
  '[data-thread-id] .hP',
];

const SENDER_SELECTORS = [
  '.gD',
  '.go[email]',
  '.yP[email]',
];

const BODY_SELECTORS = [
  '.a3s.aiL',
  '.a3s',
  '.ii.gt .a3s',
];

/** Try selectors in order and return first matching element. */
function trySelectors(selectors: string[], root: Document | Element = document): Element | null {
  for (const selector of selectors) {
    try {
      const el = root.querySelector(selector);
      if (el) return el;
    } catch (e) {
      console.warn('[gmailExtract] Selector error for "' + selector + '":', (e as Error).message);
    }
  }
  return null;
}

/** Safely extract trimmed text limited to maxLength. */
function safeText(el: Element | null, maxLength: number): string {
  if (!el) return '';
  const text = (el.textContent || '').trim();
  return text.slice(0, maxLength);
}

/** Extract sender string, preferring email attribute. */
function extractSender(el: Element | null): string {
  if (!el) return '';
  const emailAttr = el.getAttribute('email') || '';
  if (emailAttr.trim()) return emailAttr.trim().slice(0, 256);
  return safeText(el, 256);
}

/** Verify hostname belongs to Google. */
function isGoogleHost(hostname: string): boolean {
  if (!hostname) return false;
  const host = hostname.toLowerCase().trim().replace(/\\.+$/, '');
  if (host === 'google.com' || host.endsWith('.google.com')) return true;
  // international variants
  return /^(?:[a-z0-9-]+\\.)*google\\.(?:[a-z]{2,3}|co\\.[a-z]{2}|com\\.[a-z]{2})$/i.test(host);
}

/** Resolve link URL, unwrapping Google redirects and enforcing limits. */
function resolveLinkUrl(rawHref: string, baseHref = window.location.href): string | null {
  if (!rawHref) return null;
  const trimmed = rawHref.trim();
  if (!trimmed) return null;
  let parsed: URL;
  try {
    parsed = new URL(trimmed, baseHref);
  } catch (_) {
    return null;
  }
  // Google redirect wrapper
  if (isGoogleHost(parsed.hostname) && parsed.pathname.toLowerCase() === '/url') {
    const q = parsed.searchParams.get('q');
    if (q) parsed = new URL(q);
  }
  if (!['http:', 'https:'].includes(parsed.protocol)) return null;
  const final = parsed.toString();
  return final.length <= URL_MAX_CHARS ? final : null;
}

/** Main extraction function returning a structured object. */
function extractGmailMessage() {
  const subjectEl = trySelectors(SUBJECT_SELECTORS);
  const senderEl = trySelectors(SENDER_SELECTORS);
  const bodyEl = trySelectors(BODY_SELECTORS);

  if (!subjectEl && !senderEl && !bodyEl) {
    return { success: false, reason: 'no_elements_found' } as const;
  }

  const subject = safeText(subjectEl, SUBJECT_MAX_CHARS);
  const sender = extractSender(senderEl);
  const bodyText = safeText(bodyEl, BODY_MAX_CHARS);

  // Extract links from body
  const anchors = bodyEl ? Array.from(bodyEl.querySelectorAll('a[href]')) : [];
  const links: string[] = [];
  for (const a of anchors) {
    if (links.length >= LINK_MAX_COUNT) break;
    const href = a.getAttribute('href');
    const resolved = resolveLinkUrl(href || '');
    if (resolved) links.push(resolved);
  }

  return {
    success: true,
    subject,
    sender,
    bodyText,
    links,
  } as const;
}

// Listen for extraction requests from background or popup
chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg && msg.type === 'EXTRACT_GMAIL') {
    const result = extractGmailMessage();
    sendResponse(result);
    return true; // keep channel open for async (though sync here)
  }
  return false;
});

export { extractGmailMessage };
