# NVD integration

## Source and interpretation

The sole intelligence transport is HTTPS to `https://services.nvd.nist.gov/rest/json/cves/2.0`. It uses NVD API 2.0, a fixed URL, a 10-second connect/40-second request timeout, TLS certificate verification, and no redirects. Reference URLs are stored/displayed only when HTTP(S); they are never fetched by the backend.

Official API specification: https://nvd.nist.gov/developers/vulnerabilities

Official request guidance/rate limits: https://nvd.nist.gov/developers/start-here

An optional `NVD_API_KEY` is sent as an `apiKey` header, never a query string, frontend value, or audit field. NVD's documented public/keyed allowances are 5/50 requests per rolling 30 seconds. This client spaces requests at least 6.1/0.7 seconds apart and retries rate-limit/5xx/network failures at most three total attempts with bounded backoff/Retry-After. Other 4xx responses fail without retry. Other users sharing the public IP can still exhaust the upstream limit. A key is recommended; the app does not manufacture one.

Ingestion stores CVE ID, English description, publication/modification dates, references, NVD status, CVSS vector/version, and vulnerable CPE matches with inclusive/exclusive version boundaries. Preferred score order: v4.0, v3.1, v3.0, then v2; prefer the `Primary` metric within a version. Missing metrics remain null/unknown. Rejected CVEs are retained with unknown score, not deleted. The NVD CVSS v2 severity scale does not have a critical band; the NVD record honors that distinction. Inventory severity is separately labeled as configurable policy classification of the base score.

CPE match records describe applicability, not an automated installed-version match. They may include nested logical/environmental conditions; VulnWatch flattens vulnerable matches for display and does **not** claim to evaluate full CPE configuration logic. The official linked record remains the authority.

## Synchronization behavior

- A separate `python -m app.worker` process checks every minute; synchronization is due at startup, then no more often than `SYNC_INTERVAL_SECONDS` (minimum two hours). Failed attempts wait until the next interval, rather than hot-looping upstream.
- Initial sync uses the last `NVD_INITIAL_DAYS` of **modification dates** (default 30), not every historical CVE or every recently published CVE. Imported CVEs outside this range are separately enriched by exact ID: up to 25 pending identifiers per run. An unknown NVD identifier remains pending for a later run.
- Subsequent windows begin five minutes before the committed watermark, intentionally replaying overlap. Windows are capped at 119 days, below NVD's 120-day maximum. Pagination advances by actual returned entries and validates progress/index/total metadata.
- Updates are idempotent by CVE ID. Older modified timestamps never overwrite newer records. A changed score appends risk assessments for affected findings; it does not invent scanner observations or change remediation states.
- Each window is **staged then applied**: every fetched page is committed to `sync_staged_cves` as it arrives, and the window's CVEs and watermark become visible together only after the final page is stored. A failed window never exposes a partially applied range as complete. Already-fetched pages survive a failure, so the next attempt resumes from the recorded cursor instead of refetching the window. See [ADR 0005](adr/0005-staged-sync-windows.md).
- Each run records an operational row in `sync_runs`: kind (`sync`/`backfill`), status (`running`/`completed`/`failed`/`cancelled`), page counts, total pages, retry count, last page duration, and any safe error. This records what was attempted; it is not a claim that upstream data is complete.
- PostgreSQL uses a dedicated session-scoped advisory lock for the entire run, plus a visible lease timestamp. The advisory lock, not the timestamp alone, protects long-running requests. The timestamp is advisory UI metadata and can expire while a long import still holds the lock. A process crash releases the PostgreSQL lock; an unexpired five-minute lease delays a restart briefly. SQLite is only a single-process development/test fallback.
- An administrator can queue a sync through `/api/sync`, subject to a two-hour cooldown. The API does not perform external requests in a browser request. A queued request requires a running worker. The CLI one-shot is an operator tool; avoid using it to bypass upstream guidance.
- A running synchronization can be cancelled with `POST /api/sync/cancel` (administrator only). Cancellation is checked between pages, discards that window's staged rows, leaves the watermark unchanged, and marks the run `cancelled`; it never publishes a partial window.
- `last_success`, `last_attempt`, `last_error`, `watermark`, queued/running/cancelling state, pending-enrichment backlog, and the latest run's page/retry/duration metrics are available via `/api/sync`. No network failure changes the UI to a fabricated connected state.

## Explicit backfill

`python -m app.cli backfill --days N` re-reads the last `N` days of modifications (`1 <= N <= 120`). It is a deliberate operator action, not part of the scheduled loop, and it shares the advisory lock, lease, staging, and cancellation behavior of a normal run. Bounds are enforced; out-of-range or missing `--days` exits with an error instead of guessing a range. Backfill consumes upstream quota, so reserve it for a known gap rather than routine operation.

## Limits and operations

NVD can be delayed, incomplete, rate-limited, unavailable, or revise a record. No SLA, exploitability claim, automatic affected-product matching, or full-history-mirror claim is made. The code tests fixtures and upstream failure modes without network access. Run an authorized one-CVE read as a live connectivity smoke test rather than repeatedly mirroring NVD during CI.

Keep one worker per deployment, coordinate API-key use across environments, monitor failed syncs, and use backups. Large initial windows may take minutes; page staging now bounds each transaction to one page and lets a restarted run resume instead of refetching. CVE search queries the local mirror, not the live internet.
