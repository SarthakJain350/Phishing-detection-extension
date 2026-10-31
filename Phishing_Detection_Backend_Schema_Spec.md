# Backend Database Schema --- Phishing Attack Detector

**Version:** 1.0\
**Database:** PostgreSQL 16\
**Status:** Initial implementation specification\
**Aligned with:** existing PRD, TRD, App Flow Document, and UI/UX Design
Brief

## 1. Decisions confirmed

-   Store a domain/hostname only as the target reference; do not store
    full URLs.
-   Store structured evidence objects in JSONB.
-   Embed per-tool statuses in the scan row in JSONB.
-   Retain scan history for 30 days.
-   Create a new scan row for every scan; do not deduplicate or cache
    results in this schema.
-   Support clearing scan history.
-   Keep the first version small enough for a 15-day implementation.
-   Do not persist full page text, email body, subject, or raw message
    content by default.

## 2. Table: `scans`

One row represents one scan attempt, including attempts that return
partial results. Each repeated scan creates a new UUID and a new row.

  -----------------------------------------------------------------------
  Column                  PostgreSQL type         Rules / purpose
  ----------------------- ----------------------- -----------------------
  `id`                    `UUID`                  Primary key, generated
                                                  by the backend

  `target_type`           `TEXT`                  `website` or `email`

  `target_reference`      `TEXT`                  Lowercase
                                                  hostname/domain only;
                                                  no scheme, path,
                                                  credentials, query,
                                                  fragment, or whitespace

  `classification`        `TEXT`                  `phishing`,
                                                  `suspicious`, or
                                                  `likely_legitimate`

  `risk_score`            `SMALLINT`              Nullable integer
                                                  0--100; a risk
                                                  indicator, not
                                                  probability

  `evidence`              `JSONB`                 Array of structured
                                                  evidence objects

  `tool_statuses`         `JSONB`                 Object of per-tool
                                                  status summaries

  `analysis_status`       `TEXT`                  `complete`, `partial`,
                                                  or `unavailable`

  `source`                `TEXT`                  `extension`, `gmail`,
                                                  `manual`, or `system`

  `created_at`            `TIMESTAMPTZ`           Defaults to database
                                                  time
  -----------------------------------------------------------------------

### Evidence object

Example:

``` json
{
  "type": "domain_mismatch",
  "source": "heuristics",
  "severity": "high",
  "explanation": "The visible link text does not match its destination."
}
```

Allowed severity values should be validated in the application, for
example `low`, `medium`, and `high`. Treat explanations as untrusted
text and render them safely in the extension. Persist only concise
evidence needed to explain the result.

### Tool status object

Example:

``` json
{
  "heuristics": {
    "status": "complete"
  },
  "reputation": {
    "status": "unavailable",
    "reason_code": "provider_timeout"
  },
  "llm": {
    "status": "complete"
  }
}
```

Use bounded, enumerated status and reason codes in Pydantic models. Do
not store provider secrets, request headers, raw prompts, or raw
provider responses.

## 3. Privacy and domain normalization

`target_reference` must contain only a normalized hostname/domain: -
Website: extract the hostname from the submitted URL, lowercase it,
remove a trailing dot, and convert internationalized domain names to a
consistent ASCII/Punycode form if supported. - Email: derive the
reference from a relevant sender or link domain using a documented rule.
Do not store the sender's full email address. - Do not store URL paths,
query parameters, fragments, credentials, email addresses, subjects, or
page/email content in this field. - Validate hostnames using a robust
URL/domain parser in the application. The SQL check is a guardrail, not
a complete hostname validator. - Do not fetch arbitrary URLs from the
database. SSRF protection belongs in the scanning/reputation adapter.

For an email containing multiple links, this initial schema stores one
primary domain reference. If the UI needs to display multiple suspicious
domains, return them as bounded evidence objects without retaining the
full message. A separate URL table is not required for the first
version.

## 4. Analysis semantics

-   `complete`: required checks completed sufficiently to return a
    result.
-   `partial`: a result exists, but one or more checks failed or were
    skipped.
-   `unavailable`: no usable analysis result was produced; `risk_score`
    must be `NULL`.

The UI must not translate provider failures into `likely_legitimate`. Do
not assign a default score of zero when analysis is unavailable. The
classification field remains non-null in this minimal schema; for
`unavailable`, use a neutral operational placeholder only if the API
contract requires one, and ensure the UI ignores it as a verdict. Prefer
changing `classification` to nullable in a later migration if the
current API contract permits it. The backend must always use
`analysis_status` as the authority for whether a verdict is usable.

## 5. Indexes

-   `ix_scans_created_at`: efficient recent-history queries and
    retention cleanup.
-   `ix_scans_target_created_at`: recent scans for a hostname.
-   `ix_scans_classification_created_at`: filtering history by
    classification.

Avoid indexes on JSONB evidence or tool status until a measured query
requires them. Avoid storing a duplicate cache key because repeated
scans intentionally create new records.

## 6. Retention and clear-history behaviour

### 30-day retention

Run a daily maintenance task:

``` sql
DELETE FROM scans
WHERE created_at < now() - INTERVAL '30 days';
```

This statement is not self-scheduling. Wire it into a simple backend
maintenance command or scheduler and test that it removes only rows
older than 30 days. Do not run retention cleanup on every scan request.

### Clear history

Provide a backend endpoint consistent with the existing API style, for
example `DELETE /api/v1/scans`. Since the prototype has no separate user
authentication, document that this endpoint clears the local prototype's
scan history and must not be exposed to untrusted networks. Require an
explicit confirmation in the UI. If multi-user access is added later,
introduce ownership and authorization before exposing per-user deletion.

## 7. API alignment

Keep the existing endpoint plan:

-   `GET /api/v1/health`
-   `GET /api/v1/health/ready`
-   `POST /api/v1/scans/website`
-   `POST /api/v1/scans/email`
-   `GET /api/v1/scans`
-   `GET /api/v1/scans/{scan_id}`

Add `DELETE /api/v1/scans` for the agreed clear-history feature. Do not
persist the request body merely because it was accepted by a scan
endpoint.

Suggested response fields: `id`, `target_type`, `target_reference`,
`classification`, `risk_score`, `evidence`, `tool_statuses`,
`analysis_status`, `source`, `created_at`. Keep names consistent between
Pydantic schemas, SQLAlchemy models, repository code, and extension
types.

## 8. Implementation notes

-   Use SQLAlchemy 2 models and an Alembic migration; treat the SQL file
    as the reference DDL, not a substitute for the migration history.
-   Generate UUIDs in the application or use a PostgreSQL UUID default
    consistently.
-   Validate JSONB shape with Pydantic before inserting. Database checks
    only validate the top-level JSON type.
-   Use parameterized SQL/SQLAlchemy expressions.
-   Apply bounded pagination to `GET /api/v1/scans`; default to a small
    page size and cap the maximum.
-   Never log full request content or API keys.
-   Use UTC-aware timestamps.
-   Test inserts for website/email scans, all analysis states, score
    bounds, malformed evidence, history ordering, clear-history, and
    30-day cleanup.
-   Keep database connection details and API secrets in environment
    variables; never in the extension bundle.

## 9. Important implementation caveat

The existing TRD's classification set is `phishing`, `suspicious`, and
`likely_legitimate`, while the analysis status separately records
completeness. If the API contract can be adjusted before implementation,
the cleanest representation is to allow `classification = NULL` when
`analysis_status = 'unavailable'`. If the contract is already frozen as
non-null, retain the agreed enum but treat the classification as
non-authoritative whenever status is unavailable. Do not display an
unavailable scan as a legitimate result.

## 10. Acceptance checklist

-   [ ] One scan attempt creates one row with a UUID.
-   [ ] Website and email scan types are constrained to known values.
-   [ ] Target reference stores only a normalized domain/hostname.
-   [ ] No full URL, email subject, sender address, or message/page body
    is persisted by default.
-   [ ] Risk score is bounded from 0 to 100 or null.
-   [ ] Evidence is structured JSONB and tool statuses are embedded
    JSONB.
-   [ ] Complete, partial, and unavailable states remain distinct.
-   [ ] History is ordered newest-first and paginated.
-   [ ] Daily retention deletes records older than 30 days.
-   [ ] Clear-history endpoint is implemented and restricted to the
    local/trusted prototype environment.
-   [ ] Automated tests cover schema constraints and privacy
    expectations.
