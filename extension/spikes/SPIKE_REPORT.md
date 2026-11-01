# Spike Report — Phase 2 Browser Feasibility Spikes

**Phase:** 02 — Detection Foundation & Browser Feasibility
**Tasks:** 2.3.1 (Navigation Interstitial) · 2.3.2 (Gmail DOM Extraction)
**Author:** Rohan
**Date:** 2026-11-01
**Status:** Prototype complete — manual verification required in Chrome

> [!IMPORTANT]
> This is a **feasibility report**, not a verified production feature. Behaviors
> marked **Requires Chrome verification** have been analysed from documentation,
> source inspection, and known MV3 constraints but have **not been run live in
> a Chrome extension context** as of this report date. Manual verification
> steps are provided in §4.

---

## 1. Spike 1 — Chrome MV3 Navigation Warning Interstitial

### 1.1 Prototype deliverables

| File | Status |
|---|---|
| `extension/spikes/warning-interstitial/warning.html` | ✅ Created |
| `extension/spikes/warning-interstitial/warning.js` | ✅ Created |

The interstitial renders the Quiet Security palette from
`Phishing_Detection_UI_UX_Design_Brief.md §4`:

- Canvas `#F7F5F0` / Surface `#FFFFFF` (light mode default)
- Red `#B42318` / `red-soft #FDECEA` — phishing status bar, badge, and score
- Teal `#0F766E` — primary "Go back to safety" button
- Dark-mode token override via `@media (prefers-color-scheme: dark)`

The page accepts `?domain=`, `?score=`, `?reason1–3=`, `?dest=`, and
`?partial=` query parameters. All values are set via `textContent` (not
`innerHTML`) to prevent XSS.

### 1.2 MV3 Navigation Interception — Feasibility Investigation

#### Three candidate mechanisms

| Mechanism | MV3 support | Blocking? | Verdict |
|---|---|---|---|
| `webRequest` (blocking) | ❌ Removed for non-enterprise in MV3 | Would block navigation | **Not viable** for public extensions |
| `declarativeNetRequest` (DNR) | ✅ Full MV3 support | Rules-based redirect | **Most reliable** — pre-compiled rules, no JS in the critical path |
| `webNavigation.onBeforeNavigate` + `tabs.update` | ✅ Available | Soft redirect (race condition risk) | **Feasible with caveats** — see §1.3 |
| Content script link-click interception | ✅ Available | Only for in-page link clicks | **Partial** — misses direct URL entry, bookmark navigations |

#### Recommended architecture for Phase 3

Use `declarativeNetRequest` (DNR) for the blocking redirect and
`webNavigation.onBeforeNavigate` as a secondary soft-redirect for URLs that
the DNR rule misses (e.g., dynamically added rules after a scan result).

```
User navigates → URL → chrome.declarativeNetRequest → redirect to warning.html?...
                                          ↑
                             Service worker adds rule after detection result
                             (dynamic rules via chrome.declarativeNetRequest.updateDynamicRules)
```

**Key constraint:** DNR dynamic rules cap is **5,000 rules per extension**. Each
allowlisted domain must be removed from the ruleset to avoid exhausting the cap.

### 1.3 Known limitations and failure modes

#### `webNavigation.onBeforeNavigate` approach

| Risk | Detail | Mitigation |
|---|---|---|
| **Race condition** | `onBeforeNavigate` fires after the navigation is committed to the renderer; `tabs.update` may lose the race on fast connections | Use `tabs.update` with `url: warningUrl` immediately; test with slow and fast network conditions |
| **Redirect loop** | Interstitial itself triggers `onBeforeNavigate` | Filter events by URL: skip events where `url.startsWith(chrome.runtime.getURL('spikes/warning-interstitial/'))` |
| **New tab navigations** | `onBeforeNavigate` does not fire for navigations from the omnibox on the NTP | Supplement with `tabs.onCreated` + `tabs.onUpdated` listeners |
| **Cross-tab race** | `tabs.update` in the callback of `onBeforeNavigate` can cause a brief flash of the destination page before the redirect | Acceptable for the prototype; not for production |
| **Service worker suspension** | MV3 service workers suspend after ~5 s of inactivity; a suspended worker misses navigation events | Use `chrome.alarms` to keep-alive during active scan windows |

#### `declarativeNetRequest` approach

| Risk | Detail | Mitigation |
|---|---|---|
| **Dynamic rule propagation delay** | After `updateDynamicRules`, rules may take one browser event loop tick to activate | Test with a `setTimeout` guard before navigation |
| **URL pattern required upfront** | DNR redirects require a URL match pattern — works for known phishing URLs but not unknown future URLs without a preceding scan | Only use DNR for URLs that have already been scanned and classified; fall back to `webNavigation` for new navigations |
| **5,000 rule cap** | Hits a hard limit after many scanned URLs | Implement LRU eviction: remove oldest dynamic rules when count approaches limit |

### 1.4 Redirect loop prevention (confirmed design)

`warning.js` checks if `window.history.length > 1` before using `history.back()`.
In the service worker:

```javascript
// background.js (production pseudocode — not in this spike)
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  // Prevent interstitial from intercepting itself
  if (details.url.startsWith(chrome.runtime.getURL(''))) return;

  // Check session allowlist
  chrome.storage.session.get([`allowlist_${new URL(details.url).hostname}`], (items) => {
    if (Object.keys(items).length > 0) return; // Allowlisted — skip
    // Trigger redirect...
  });
});
```

The session allowlist (`chrome.storage.session`) is cleared on browser restart
and extension reload — no persistent bypass of the warning for new sessions.

---

## 2. Spike 2 — Gmail DOM Extraction Prototype

### 2.1 Prototype deliverable

| File | Status |
|---|---|
| `extension/spikes/gmail-extraction/extract.js` | ✅ Created |

### 2.2 Gmail DOM selector analysis

The following selectors were identified from public sources, open-source
Gmail extension projects (e.g., InboxSDK), and empirical inspection:

| Field | Primary selector | Fallback selectors | Confidence |
|---|---|---|---|
| Subject | `.hP` | `h2.ha`, `[data-thread-id] .hP` | Medium — `.hP` is widely referenced |
| Sender | `.gD` (with `email` attr) | `.go[email]`, `.yP[email]` | Medium — attribute varies by Gmail version |
| Body text | `.a3s.aiL` | `.a3s`, `.ii.gt .a3s` | Medium — `.a3s` is stable; `.aiL` modifier may be absent |
| Body links | `a[href]` within body el | — | High — standard DOM query |

**Confidence levels:**
- **High:** Query works reliably across Gmail versions (rarely breaks)
- **Medium:** Query known to work but has broken before in Gmail updates
- **Low:** Speculative; verification required before relying on it

> [!WARNING]
> Gmail's DOM is an implementation detail, not a public API. Google has
> changed these selectors multiple times without notice. Any production
> integration must include a graceful degradation path for when selectors
> return empty — the `extract.js` prototype implements this via the
> `{ success: false, reason: "..." }` return shape.

### 2.3 Boundary conditions handled

| Scenario | Prototype behavior |
|---|---|
| User is in inbox list view (no open message) | `isMessageOpen()` returns false → `{ success: false, reason: "no_open_message" }` |
| Message open but body selector misses | `bodyEl` is null → `{ success: false, reason: "body_extraction_failed" }` |
| Subject selector misses | `subject = ""` (empty string) — not a hard failure |
| Sender selector misses | `sender = ""` (empty string) — not a hard failure |
| No links in email body | `links = []` — valid, not a failure |
| More than 10 links present | Capped at `LINK_MAX_COUNT = 10` |
| Body text longer than 3,000 chars | Truncated at `BODY_MAX_CHARS = 3000` |
| `javascript:` or `data:` links in body | Filtered by URL protocol check — excluded from output |
| Non-Gmail domain | `{ success: false, reason: "not_on_gmail" }` |
| DOM selector throws (invalid CSS) | Caught in `trySelectors` — skipped to next candidate |

### 2.4 Known limitations

| Limitation | Impact | Notes |
|---|---|---|
| **Selector fragility** | Selectors may break silently on Gmail update | Production code must monitor extraction failure rates and alert when `reason: "body_extraction_failed"` exceeds a threshold |
| **Collapsed threads** | `.a3s.aiL` may not be present for collapsed (quoted) reply portions of a thread | Only the most recent expanded message is extracted |
| **Mobile Gmail** | Selector names differ entirely from desktop | This spike targets desktop web Gmail only |
| **Gmail dark mode** | DOM structure unchanged — extraction unaffected | Cosmetic only |
| **Rate of Gmail DOM change** | No SLA from Google | Plan for quarterly selector verification |
| **Content script timing** | Script must run after Gmail's React-style app hydrates | Use `document_idle` run-at in manifest, not `document_start` |
| **Inline images and attachments** | Not extracted — body text only | Sufficient for the planned analysis scope |

### 2.5 Privacy verification

- ✅ `bodyText` is truncated at 3,000 chars — matches `EmailScanRequest.body_text` schema constraint
- ✅ `links` capped at 10 — matches `EmailScanRequest.links` schema constraint
- ✅ No `console.log` calls in the extraction path emit body text or link URLs
- ✅ The module does NOT call `fetch()`, `XMLHttpRequest`, or any Chrome extension
  messaging API unless the message listener receives an explicit `EXTRACT_GMAIL` trigger
- ✅ No data is sent to the backend or any third party by the spike code itself

---

## 3. Shared findings and architecture recommendations

### 3.1 Phase 3 wiring plan (not in scope for Phase 2)

```
Popup/panel user action
    │
    ▼
chrome.tabs.sendMessage({ type: 'EXTRACT_GMAIL' }, tabId)
    │
    ▼ (content script on mail.google.com)
extractGmailMessage() → { success, subject, sender, bodyText, links }
    │
    ▼
chrome.runtime.sendMessage({ type: 'SCAN_EMAIL', payload: result })
    │
    ▼ (service worker)
POST /api/v1/scans/email  ← backend FastAPI endpoint (Phase 1)
    │
    ▼
ScanResponse { classification, risk_score, evidence, ... }
    │
    ▼
chrome.tabs.sendMessage({ type: 'SCAN_RESULT', data: response }, tabId)
    │
    ▼ (content script renders inline Gmail panel)
```

### 3.2 Manifest additions required (Phase 3 — NOT in current manifest)

```jsonc
// manifest.json additions needed for production Gmail integration:
{
  "permissions": [
    "activeTab",
    "scripting",
    "webNavigation",       // for navigation interception
    "storage",             // for chrome.storage.session allowlist
    "declarativeNetRequest" // for DNR redirect rules
  ],
  "host_permissions": [
    "https://mail.google.com/*",    // for Gmail content script
    "http://127.0.0.1:8000/*",
    "http://localhost:8000/*"
  ],
  "content_scripts": [
    {
      "matches": ["https://mail.google.com/*"],
      "js": ["gmail-content-script.js"],
      "run_at": "document_idle"
    }
  ],
  "web_accessible_resources": [
    {
      "resources": ["warning.html", "warning.js"],
      "matches": ["<all_urls>"]
    }
  ]
}
```

> [!IMPORTANT]
> Adding `https://mail.google.com/*` to `host_permissions` is a **significant
> privacy-scope expansion** that requires user consent, Chrome Web Store
> review, and a clear privacy disclosure. This must be justified in the
> extension's store listing and privacy policy before Phase 3 integration.

---

## 4. Manual verification steps

### 4.1 Warning interstitial — standalone browser test

> **Environment:** Any browser, no extension required for basic UI verification.

1. Open a terminal and navigate to `extension/spikes/warning-interstitial/`.
2. Start a local HTTP server:
   ```bash
   python -m http.server 8080
   ```
3. Open Chrome and navigate to:
   ```
   http://localhost:8080/warning.html?domain=paypal.com.evil-verify.xyz&score=88&reason1=Misleading+subdomain+detected&reason2=Urgency+language+in+page+text&dest=https%3A%2F%2Fpaypal.com.evil-verify.xyz%2Flogin
   ```
4. **Verify:**
   - Domain `paypal.com.evil-verify.xyz` is displayed in the destination box.
   - Score `88 / 100` is shown.
   - Two reasons are listed as bullet points.
   - "Go back to safety" button is focused on load.
   - Pressing `Escape` activates the back action.
   - Clicking "Continue anyway" shows the amber confirmation message.
   - Clicking "Go back to safety" calls `history.back()` (browser back button).

5. Test partial analysis state:
   ```
   http://localhost:8080/warning.html?domain=test.com&score=75&partial=1
   ```
   - Verify the partial analysis notice panel appears below the reasons.

6. Test dark mode (if system is in dark mode or using Chrome DevTools emulation):
   - Verify canvas is `#111820` and text is light.

### 4.2 Warning interstitial — Chrome extension integration test

> **Requires Chrome Extension unpacked load — NOT performed as of this report.**

**Prerequisite:** Build the production extension (`npm run build` in `extension/`),
then load `extension/dist/` as an unpacked extension in `chrome://extensions/`.

Steps for future Chrome verification:
1. Add `warning.html` and `warning.js` to `web_accessible_resources` in manifest.
2. In the service worker (`background.js`), add a temporary `webNavigation.onBeforeNavigate`
   listener that redirects any navigation to `http://phishing-test.example.com` to
   `warning.html?domain=phishing-test.example.com&score=88&dest=http://phishing-test.example.com`.
3. Navigate to `http://phishing-test.example.com` in a Chrome tab.
4. Verify the interstitial appears and both buttons work correctly.
5. Verify that clicking "Go back to safety" returns to the previous tab/page.
6. Verify clicking "Continue anyway" navigates to the destination.
7. Verify the interstitial does NOT intercept its own URL (no redirect loop).

**Status:** ⚠️ **Requires Chrome verification — not yet tested in extension context.**

### 4.3 Gmail DOM extraction — browser console test

> **Environment:** Desktop Chrome with a Gmail account signed in.**

1. Open Gmail in Chrome (`https://mail.google.com/`).
2. Click on any email to open it (not just preview in the reading pane — the
   full thread view).
3. Open Chrome DevTools (`F12`) → Console.
4. Copy the entire contents of `extension/spikes/gmail-extraction/extract.js`
   and paste into the Console.
5. Run:
   ```javascript
   extractGmailMessage()
   ```
6. **Verify the success path:**
   - `result.success` is `true`.
   - `result.subject` contains the email subject (non-empty).
   - `result.sender` contains the sender email or name.
   - `result.bodyText` contains readable text (max 3,000 chars).
   - `result.links` is an array (may be empty if no links in email).

7. **Verify the failure path:**
   - Navigate to the inbox list view (click "Inbox" in the sidebar).
   - Run `extractGmailMessage()` again.
   - `result.success` should be `false` and `result.reason` should be
     `"no_open_message"`.

8. **Verify truncation:**
   - Open a very long email (newsletter with many links).
   - Verify `result.bodyText.length <= 3000`.
   - Verify `result.links.length <= 10`.

9. **Verify no console leakage:**
   - Inspect the console output during extraction.
   - Confirm that no email body text or URLs appear in `console.log`/`console.warn`
     output from `extract.js`.

**Status:** ⚠️ **Requires live Gmail account verification — not yet tested.**

---

## 5. Files changed

```
extension/spikes/
├── warning-interstitial/
│   ├── warning.html   (new — standalone Quiet Security interstitial prototype)
│   └── warning.js     (new — URL param parser, action handlers, allowlist logic)
├── gmail-extraction/
│   └── extract.js     (new — Gmail DOM extraction prototype)
└── SPIKE_REPORT.md    (this file)
```

**Files NOT modified:**
- `extension/public/manifest.json` — production manifest unchanged
- `extension/src/` — production React/TypeScript source unchanged
- `extension/dist/` — production build unchanged
- `backend/` — no backend changes
- Any original project specification documents

---

## 6. Deviations from Plan 02-03

| Deviation | Reason |
|---|---|
| `warning.js` "Continue anyway" uses `sessionStorage` as a fallback | `chrome.storage.session` is unavailable in the `file://` standalone test context. The production path uses `chrome.storage.session` correctly; fallback is clearly labeled and logged. |
| No live Chrome extension verification performed | Plan 02-03 specified manual verification steps; as noted in §4, browser behavior is documented as requiring verification — not claimed as tested. The user instruction specifically said "Do not claim browser behavior is verified unless actually tested in Chrome." |
| `extract.js` exports via `module.exports` for Node.js test harness compatibility | Plan required graceful fallback handling — this enables unit testing of `safeText`, `extractLinks`, and `extractSender` without a browser DOM. Production content-script usage is unaffected. |

---

## 7. Recommended next steps (Phase 3 prerequisites)

1. **Chrome extension verification** — Load as unpacked extension and run manual
   tests from §4.2 and §4.3 before committing to the Phase 3 integration plan.
2. **Gmail selector monitoring** — Before wiring `extract.js` to the production
   backend call, add a selector-health check that logs `{ reason, selectorsTried }`
   to a local extension diagnostic endpoint (no PII).
3. **Manifest scope review** — Get privacy team sign-off on `host_permissions`
   expansion to `https://mail.google.com/*` before Phase 3.
4. **DNR rule management** — Design the dynamic rule lifecycle (add on scan result,
   remove on allowlist or session end) with the 5,000-rule cap in mind.
5. **Service worker keep-alive** — Implement `chrome.alarms`-based keepalive
   before relying on `webNavigation.onBeforeNavigate` for navigation interception.
