# 0005 — Stage NVD pages before applying a synchronization window

- **Status:** Accepted
- **Date:** 2026-11-21

## Context

Synchronization originally streamed every page of a date window into one database transaction and committed CVEs, the watermark, and the audit event together. That was atomic and safe, but it meant a failure on the last page discarded the entire window's work and refetched everything on retry. Large initial or backfill windows could take many minutes inside one growing transaction, and an operator had no visibility into progress or a way to stop a runaway run.

## Decision

Persist each fetched page to `sync_staged_cves` as it arrives, keyed by `sync_runs.id`, and apply the staged rows to `cve_records`/`vulnerabilities` only after the final page of the window has been stored. Inside `sync_window` the sequence is:

1. Open or resume a `sync_runs` row for the window, recording `cursor_index`, `pages_fetched`, `pages_total`, `retry_count`, and `last_page_ms`.
2. Fetch a page, deduplicate identifiers already staged for this run, stage the rows, update the cursor, and commit.
3. On the last page, apply all staged rows in a single transaction together with the watermark and audit event, then discard the staged rows.
4. On failure, roll back the window's apply step; staged rows and the cursor remain so the next attempt resumes at the recorded index. A `failed` run is resumable: the next synchronization finishes any window that still has staged pages, and retires a failed run whose staged pages are already gone.

A page that reports fewer entries than its own `totalResults` while the cursor is still below that total is treated as a pagination fault rather than completion, so the watermark is never advanced over records the upstream said exist.

A running window may be cancelled through `POST /api/sync/cancel`. Cancellation is checked between pages, discards the staged rows, leaves the watermark unchanged, and marks the run `cancelled`. A new run clears any stale cancellation flag.

Backfill is an explicit operator action: `python -m app.cli backfill --days N` with `1 <= N <= 120`, sharing the same advisory lock, lease, staging, and cancellation behavior as scheduled synchronization.

## Consequences

- A failed window no longer discards already-fetched pages, so retries resume instead of refetching.
- A checkpoint can never present a partially applied window as complete, because the watermark and the CVE rows become visible in the same commit as the apply step.
- Staging rows are transient. They are removed on success and on cancellation, and are left in place only for a resumable failed run.
- `sync_runs` is an operational audit trail of runs, not a claim of upstream correctness. It records what was attempted, not whether NVD data was complete.
- The design assumes one worker per deployment, consistent with the existing advisory lock. Concurrent backfills are excluded by the same lock rather than by a separate queue.
- Staged rows are not deduplicated against `cve_records`; applying an older modification for an existing CVE still defers to the existing `modified_at` guard in `upsert_cve`.

## Alternatives considered

- **Stream and commit per page with an advanced watermark:** simpler, but would expose a partially applied window as complete, which the issue explicitly forbids.
- **Keep one transaction per window:** preserves atomicity but cannot resume, and holds a large transaction open for the whole window.
- **External queue/worker pool:** deferred to issue #29's scale work; unnecessary for a single-worker small-team deployment.
