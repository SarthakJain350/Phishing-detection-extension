/**
 * Tests for Browser Feasibility Spikes:
 * - warning.js: destination validation, hostname normalization, allowlist safety.
 * - extract.js: Google /url redirect unwrapper, host detection, 2048-char cap.
 */

const { describe, it } = require('node:test');
const assert = require('node:assert/strict');

const {
  isGoogleHost,
  resolveLinkUrl,
  URL_MAX_CHARS,
  extractLinks,
} = require('../gmail-extraction/extract.js');

const {
  normalizeHostname,
  validateDestination,
} = require('../warning-interstitial/warning.js');

// ===========================================================================
// 1. Google Host Detection Tests
// ===========================================================================

describe('isGoogleHost', () => {
  it('accepts legitimate google.com and its subdomains', () => {
    assert.equal(isGoogleHost('google.com'), true);
    assert.equal(isGoogleHost('www.google.com'), true);
    assert.equal(isGoogleHost('mail.google.com'), true);
    assert.equal(isGoogleHost('support.google.com'), true);
  });

  it('accepts legitimate international ccTLD variants', () => {
    assert.equal(isGoogleHost('google.co.uk'), true);
    assert.equal(isGoogleHost('www.google.co.uk'), true);
    assert.equal(isGoogleHost('google.de'), true);
    assert.equal(isGoogleHost('google.ca'), true);
  });

  it('rejects deceptive lookalikes (evilgoogle.com, notgoogle.com)', () => {
    assert.equal(isGoogleHost('evilgoogle.com'), false);
    assert.equal(isGoogleHost('notgoogle.com'), false);
    assert.equal(isGoogleHost('google.evil.com'), false);
    assert.equal(isGoogleHost('fake-google.com'), false);
  });

  it('handles null, undefined, empty, and trailing dots', () => {
    assert.equal(isGoogleHost(''), false);
    assert.equal(isGoogleHost(null), false);
    assert.equal(isGoogleHost(undefined), false);
    assert.equal(isGoogleHost('www.google.com.'), true);
  });
});

// ===========================================================================
// 2. Google /url Redirect Unwrapping & URL Validation Tests
// ===========================================================================

describe('resolveLinkUrl — Google redirect wrappers', () => {
  it('unwraps a recognized Google /url redirect to its true HTTP/HTTPS destination', () => {
    const raw = 'https://www.google.com/url?q=https%3A%2F%2Fpaypal.com.account-update.xyz%2Flogin&source=gmail';
    const resolved = resolveLinkUrl(raw);
    assert.equal(resolved, 'https://paypal.com.account-update.xyz/login');
  });

  it('unwraps international Google ccTLD redirect wrappers', () => {
    const raw = 'https://www.google.co.uk/url?q=https%3A%2F%2Fphish.example.com%2Ftest';
    const resolved = resolveLinkUrl(raw);
    assert.equal(resolved, 'https://phish.example.com/test');
  });

  it('preserves ordinary non-wrapper links', () => {
    const raw = 'https://legit-site.com/about';
    const resolved = resolveLinkUrl(raw);
    assert.equal(resolved, 'https://legit-site.com/about');
  });

  it('preserves unrelated Google links that are not /url redirects', () => {
    const raw = 'https://support.google.com/mail/answer/12345';
    const resolved = resolveLinkUrl(raw);
    assert.equal(resolved, 'https://support.google.com/mail/answer/12345');
  });

  it('preserves links on deceptive lookalike hosts without unwrapping', () => {
    // If an attacker hosts an evil redirector at evilgoogle.com/url?q=...,
    // evilgoogle.com must NOT be treated as Google; the link stays evilgoogle.com
    const raw = 'https://evilgoogle.com/url?q=https%3A%2F%2Ftarget.com';
    const resolved = resolveLinkUrl(raw);
    assert.equal(resolved, 'https://evilgoogle.com/url?q=https%3A%2F%2Ftarget.com');
  });

  it('drops Google wrapper when destination scheme is unsafe (javascript:, data:)', () => {
    const raw = 'https://www.google.com/url?q=javascript%3Aalert(1)';
    const resolved = resolveLinkUrl(raw);
    assert.equal(resolved, null);
  });

  it('drops Google wrapper when q parameter is malformed', () => {
    const raw = 'https://www.google.com/url?q=not-a-valid-url';
    const resolved = resolveLinkUrl(raw);
    assert.equal(resolved, null);
  });

  it('handles Google /url link with missing q parameter gracefully', () => {
    const raw = 'https://www.google.com/url?other=123';
    const resolved = resolveLinkUrl(raw);
    assert.equal(resolved, 'https://www.google.com/url?other=123');
  });
});

// ===========================================================================
// 3. 2,048-Character URL Limit Tests
// ===========================================================================

describe('resolveLinkUrl — 2,048 Character Length Boundary', () => {
  it('accepts links at or below the 2,048-character limit', () => {
    const padding = 'a'.repeat(2048 - 'https://example.com/'.length);
    const validUrl = 'https://example.com/' + padding;
    assert.equal(validUrl.length, 2048);
    const resolved = resolveLinkUrl(validUrl);
    assert.equal(resolved, validUrl);
  });

  it('discards links exceeding 2,048 characters without silent truncation', () => {
    const oversizePadding = 'a'.repeat(2049 - 'https://example.com/'.length);
    const oversizeUrl = 'https://example.com/' + oversizePadding;
    assert.equal(oversizeUrl.length, 2049);
    const resolved = resolveLinkUrl(oversizeUrl);
    assert.equal(resolved, null, 'Oversize URL must be dropped completely, not truncated');
  });

  it('discards unwrapped Google redirect targets exceeding 2,048 characters', () => {
    const longTarget = 'https://example.com/' + 'b'.repeat(2100);
    const wrapped = 'https://www.google.com/url?q=' + encodeURIComponent(longTarget);
    const resolved = resolveLinkUrl(wrapped);
    assert.equal(resolved, null);
  });
});

// ===========================================================================
// 4. Warning Interstitial Destination Validation Tests
// ===========================================================================

describe('normalizeHostname', () => {
  it('lowercases and strips whitespace and trailing dots', () => {
    assert.equal(normalizeHostname('  Example.COM.  '), 'example.com');
    assert.equal(normalizeHostname('Paypal.co.uk.'), 'paypal.co.uk');
    assert.equal(normalizeHostname(''), '');
    assert.equal(normalizeHostname(null), '');
  });
});

describe('validateDestination — Allowlist Safety Boundary', () => {
  it('accepts valid HTTP and HTTPS destinations matching the expected domain', () => {
    const res1 = validateDestination('https://evil-phish.xyz/login?id=1', 'evil-phish.xyz');
    assert.equal(res1.valid, true);
    assert.equal(res1.hostname, 'evil-phish.xyz');
    assert.equal(res1.url, 'https://evil-phish.xyz/login?id=1');

    const res2 = validateDestination('http://test.co.uk/path', 'test.co.uk.');
    assert.equal(res2.valid, true);
    assert.equal(res2.hostname, 'test.co.uk');
  });

  it('rejects missing or empty destination', () => {
    assert.equal(validateDestination('', 'example.com').valid, false);
    assert.equal(validateDestination(null, 'example.com').valid, false);
    assert.equal(validateDestination('   ', 'example.com').valid, false);
  });

  it('rejects invalid schemes (javascript:, data:, ftp:, file:)', () => {
    assert.equal(validateDestination('javascript:alert(1)', 'example.com').valid, false);
    assert.equal(validateDestination('data:text/html,<h1>phish</h1>', 'example.com').valid, false);
    assert.equal(validateDestination('ftp://example.com/file', 'example.com').valid, false);
  });

  it('rejects malformed destination URLs', () => {
    assert.equal(validateDestination('not-a-valid-url', 'example.com').valid, false);
    assert.equal(validateDestination('http://', 'example.com').valid, false);
  });

  it('rejects hostname mismatches between destination and expected warning domain', () => {
    // If interstitial was opened for evil.com, but dest is paypal.com (or vice versa), reject!
    const res1 = validateDestination('https://paypal.com/signin', 'evil.com');
    assert.equal(res1.valid, false);
    assert.match(res1.error, /Destination host mismatch/);

    const res2 = validateDestination('https://evil.com/login', 'paypal.com');
    assert.equal(res2.valid, false);
  });
});
