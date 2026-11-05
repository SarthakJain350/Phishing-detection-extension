# Privacy Gate — Google Safe Browsing Integration
## Status: PENDING EXPLICIT OWNER SIGN-OFF (Live requests blocked by default; offline adapter & tests complete)
## Date: 2026-11-03

---

## 1. Data Sent to Google Safe Browsing

The Safe Browsing Lookup API v4 (`threatMatches:find`) endpoint receives a POST request containing one or more URL entries in the `threatInfo.threatEntries` array. Each entry has a single `"url"` field.

For website scans, the URL submitted to Google is sanitized before lookup. The URL fragment is removed, and query parameters whose names match the adapter's defined sensitive-parameter list are removed. Remaining query parameters may still be transmitted.

**Example:**

Original URL:
```text
https://suspicious-bank-login.example.com/verify?token=abc123&utm_source=email
```

URL submitted after sanitization:
```text
https://suspicious-bank-login.example.com/verify?utm_source=email
```

The submitted URL may include:
- Scheme (e.g. `https://`)
- Full hostname (including subdomains)
- Path segments (e.g. `/verify`)
- Remaining query parameters, excluding parameters removed by the sanitizer

The URL fragment (e.g. `#anchor` or `#access_token=...`) is stripped server-side using `urllib.parse.urldefrag()` before submission. Google Safe Browsing evaluates server resources and does not process URL fragments.

**Privacy limitation:** Sanitization is based on query-parameter names. Sensitive information under an unexpected parameter name, or embedded in the URL path, may still be transmitted to Google.

## 2. What Leaves the Application

| Data component | Sent externally? | Stored locally? |
|---|---|---|
| Sanitized URL (scheme + host + path + remaining query parameters) | YES — to Google | No (only hostname is stored in DB) |
| URL fragment (`#anchor`) | No | No |
| Page title | No | No |
| Visible page text | No | No |
| API key | YES — in URL query parameter `?key=…` over HTTPS | Server-side only, via environment variable |
| Scan result / evidence | No | Yes — hostname + result stored in DB |
| User identity / cookies | No | No |
| Email content | No | No |

**The sanitized URL is sent to Google but NOT stored in our own database.** The local database stores only the normalized hostname (`target_reference`), as it always has.

**Privacy limitation:** The sanitizer removes URL fragments and selected query parameters based on their names. Other query parameters and sensitive information embedded in the URL path may still be transmitted to Google.

## 3. Sensitive URL Contents

URLs submitted for scanning may contain:

- **Authentication tokens** in query parameters (e.g. `?token=…`, `?reset=…`)
- **Session identifiers** (e.g. `?session_id=…`)
- **PII in path or query** (e.g. `/users/12345/profile`)
- **Tracking parameters** (e.g. `utm_source`, `fbclid`)
- **Sensitive search terms** (e.g. medical or financial queries)

When a user triggers a manual scan, they are actively asking the detector to
analyze a URL they are visiting. The act of submitting the URL to a reputation
provider is analogous to a browser's built-in Safe Browsing check, which
performs the same operation. However, this tool should make the data flow
visible.

---

## 4. Google Safe Browsing Data Handling

From [Google Safe Browsing Terms of Service](https://developers.google.com/safe-browsing/terms):

- URLs submitted to the Lookup API are sent to Google and may be logged for spam/abuse prevention and service reliability.
- **Data Retention Notice (Unverified Claim):** Historical public documentation noted that Google may retain submitted URLs for up to 2 weeks for operational purposes. However, this specific 2-week window is unverified in current formal contract terms. Data retention is governed by Google's applicable APIs Terms of Service and Privacy Policy.
- Submitted URLs are not used to personalize Google products for end users.
- The API is provided under Google APIs Terms of Service.

**Key implication:** Sanitized URLs are transmitted to Google Safe Browsing through the Lookup API. URL fragments and query parameters matching the adapter's defined sensitive-parameter list are removed before submission. However, remaining query parameters and sensitive information embedded in URL paths may still be transmitted. Google may retain submitted request data according to its applicable infrastructure logging and data-retention policies.

This differs from the hash-based Update API, which hashes URLs locally before sending a hash prefix. The Lookup API is simpler to implement, but its privacy trade-offs require explicit understanding and acceptance by the system owner.

## 5. Current Policy Decision & Gate Status

**Privacy Gate Status: PENDING EXPLICIT OWNER APPROVAL**

Live Safe Browsing requests remain disabled by default. The adapter and its tests are implemented, but live integration must not be enabled until the project owner explicitly approves it.

When the project owner explicitly approves enabling live Safe Browsing requests:

1. The sanitized URL will be sent to Google Safe Browsing ONLY for website scans triggered by the user (source = `manual_website` or `auto_website`).
2. The full URL is NEVER logged on the backend server. Only the normalized hostname (`target_reference`) may appear in structured logs.
3. The API key is stored exclusively in the server `.env` file and never sent to the extension, included in API responses, or written to logs.
4. Reputation integration remains disabled by default whenever the key is absent.
5. Email reputation integration is deferred to a future phase.