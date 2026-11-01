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
  isReferrerSuspicious,
  determineSafeBackAction,
  handleGoBack,
  stepContinueFlow,
  recordSessionAllowlist,
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

// ===========================================================================
// 4. Safe Back Action & Referrer Guard Tests
// ===========================================================================

describe('determineSafeBackAction & handleGoBack', () => {
  it('identifies suspicious referrers matching or subdomaining the warning domain', () => {
    assert.equal(isReferrerSuspicious('https://evil-phish.xyz/login', 'evil-phish.xyz'), true);
    assert.equal(isReferrerSuspicious('http://sub.evil-phish.xyz/path', 'evil-phish.xyz'), true);
    assert.equal(isReferrerSuspicious('https://evil-phish.xyz:8080/test', 'evil-phish.xyz'), true);
    assert.equal(isReferrerSuspicious('https://google.com/search?q=test', 'evil-phish.xyz'), false);
    assert.equal(isReferrerSuspicious('', 'evil-phish.xyz'), false);
    assert.equal(isReferrerSuspicious(null, 'evil-phish.xyz'), false);
  });

  it('aborts history.back() when referrer matches the suspicious domain even if history > 1', () => {
    // If user was referred by the phishing page, history.back() would return to the phishing page
    const action = determineSafeBackAction(5, 'https://evil-phish.xyz/login', 'evil-phish.xyz');
    assert.equal(action, 'close_or_blank');
  });

  it('permits history_back when history.length > 1 and referrer is safe', () => {
    const action = determineSafeBackAction(3, 'https://safe-search.com/q', 'evil-phish.xyz');
    assert.equal(action, 'history_back');

    const actionEmptyRef = determineSafeBackAction(2, '', 'evil-phish.xyz');
    assert.equal(actionEmptyRef, 'history_back');
  });

  it('falls back to close_or_blank when history length <= 1', () => {
    const action = determineSafeBackAction(1, 'https://safe-search.com', 'evil-phish.xyz');
    assert.equal(action, 'close_or_blank');
  });

  it('handleGoBack invokes history.back() on safe history navigation', () => {
    let backCalled = false;
    let replaceCalledWith = null;

    const mockHistory = { length: 3, back: () => { backCalled = true; } };
    const mockWindow = { location: { replace: (url) => { replaceCalledWith = url; } } };

    const result = handleGoBack(mockHistory, 'https://safe.com', 'evil.com', mockWindow);
    assert.equal(result, 'history_back');
    assert.equal(backCalled, true);
    assert.equal(replaceCalledWith, null);
  });

  it('handleGoBack routes to about:blank and does not call history.back() when referrer is suspicious', () => {
    let backCalled = false;
    let replaceCalledWith = null;

    const mockHistory = { length: 4, back: () => { backCalled = true; } };
    const mockWindow = { location: { replace: (url) => { replaceCalledWith = url; } } };

    const result = handleGoBack(mockHistory, 'https://evil.com/phish', 'evil.com', mockWindow);
    assert.equal(result, 'close_or_blank');
    assert.equal(backCalled, false, 'history.back() must not be called when referrer is suspicious');
    assert.equal(replaceCalledWith, 'about:blank');
  });
});

// ===========================================================================
// 5. Deliberate Two-Step "Continue Anyway" Flow Tests
// ===========================================================================

describe('stepContinueFlow — Deliberate Confirmation State Machine', () => {
  const dest = 'https://phish-target.xyz/login';
  const domain = 'phish-target.xyz';

  it('first click transitions to armed state without navigating or allowlisting', () => {
    const initialState = { armed: false };
    const result = stepContinueFlow(initialState, dest, domain);

    assert.equal(result.step, 'armed');
    assert.equal(result.state.armed, true);
    assert.equal(result.state.validation.valid, true);
    assert.equal(result.state.validation.hostname, 'phish-target.xyz');
    assert.equal(result.state.validation.url, 'https://phish-target.xyz/login');
  });

  it('second click on armed state confirms deliberate action', () => {
    const armedState = {
      armed: true,
      validation: { valid: true, hostname: domain, url: dest },
    };

    const result = stepContinueFlow(armedState, dest, domain);

    assert.equal(result.step, 'confirmed');
    assert.equal(result.state.armed, false);
    assert.equal(result.state.validation.hostname, 'phish-target.xyz');
  });

  it('invalid destination never arms confirmation state', () => {
    const initialState = { armed: false };
    const result = stepContinueFlow(initialState, 'javascript:alert(1)', domain);

    assert.equal(result.step, 'error');
    assert.equal(result.state.armed, false);
    assert.match(result.error, /Unsafe destination scheme/);
  });

  it('host mismatch never arms confirmation state', () => {
    const initialState = { armed: false };
    const result = stepContinueFlow(initialState, 'https://other-site.com/login', domain);

    assert.equal(result.step, 'error');
    assert.equal(result.state.armed, false);
    assert.match(result.error, /Destination host mismatch/);
  });
});

// ===========================================================================
// 6. Session Allowlist Storage Tests (Mocks)
// ===========================================================================

describe('recordSessionAllowlist — Storage Resilience & Failure Handling', () => {
  it('successfully persists allowlist entry via chrome.storage.session', (t, done) => {
    let capturedData = null;
    const mockChrome = {
      storage: {
        session: {
          set: (data, callback) => {
            capturedData = data;
            callback();
          },
        },
      },
      runtime: { lastError: null },
    };

    recordSessionAllowlist('phish-target.xyz', { chrome: mockChrome }, (err) => {
      assert.equal(err, null);
      assert.deepEqual(capturedData, { 'allowlist_phish-target.xyz': true });
      done();
    });
  });

  it('reports error when chrome.storage.session.set fails via runtime.lastError', (t, done) => {
    const mockChrome = {
      storage: {
        session: {
          set: (data, callback) => {
            callback();
          },
        },
      },
      runtime: { lastError: { message: 'QUOTA_BYTES quota exceeded for session storage' } },
    };

    recordSessionAllowlist('phish-target.xyz', { chrome: mockChrome }, (err) => {
      assert.ok(err instanceof Error);
      assert.match(err.message, /QUOTA_BYTES quota exceeded/);
      done();
    });
  });

  it('successfully persists allowlist entry via standalone sessionStorage fallback', (t, done) => {
    let savedKey = null;
    let savedVal = null;
    const mockSessionStorage = {
      setItem: (k, v) => {
        savedKey = k;
        savedVal = v;
      },
    };

    recordSessionAllowlist('test-site.org', { chrome: null, sessionStorage: mockSessionStorage }, (err) => {
      assert.equal(err, null);
      assert.equal(savedKey, 'allowlist_test-site.org');
      assert.equal(savedVal, 'true');
      done();
    });
  });

  it('reports error when standalone sessionStorage throws an exception', (t, done) => {
    const mockSessionStorage = {
      setItem: () => {
        throw new Error('SecurityError: The operation is insecure');
      },
    };

    recordSessionAllowlist('test-site.org', { chrome: null, sessionStorage: mockSessionStorage }, (err) => {
      assert.ok(err instanceof Error);
      assert.match(err.message, /The operation is insecure/);
      done();
    });
  });

  it('rejects invalid or empty hostname without attempting storage write', (t, done) => {
    recordSessionAllowlist('', {}, (err) => {
      assert.ok(err instanceof Error);
      assert.match(err.message, /Invalid hostname/);
      done();
    });
  });
});
