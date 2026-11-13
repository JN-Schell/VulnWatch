# API reference

All paths begin `/api`. Except `/health` and `/auth/login`, every endpoint requires a server-side session cookie. `/openapi.json` returns the complete machine-readable schema to authenticated readers. JSON validation errors contain safe field paths, not password/upload values. Writes use JSON unless marked multipart.

## Authentication flow

```sh
curl -c cookies.txt -H 'Origin: http://localhost:8080' \
  -H 'Content-Type: application/json' \
  --data '{"email":"you@example.com","password":"YOUR_PASSWORD"}' \
  http://localhost:8080/api/auth/login
```

Use a private password entry mechanism in real scripts; the illustrative literal above can leak through shell history. Login returns `{user, csrf_token}` and an HttpOnly session cookie. Send that CSRF token as `X-CSRF-Token`, the cookie, and an exact trusted `Origin` for every authenticated write. `/auth/session` returns the current user/token for a page reload. Logout revokes the database session and clears the cookie. Sessions expire absolutely, not on a sliding refresh.

| Method / path | Minimum permission | Purpose |
| --- | --- | --- |
| GET `/health` | Public | Database connectivity, no inventory |
| POST `/auth/login` | Public + trusted Origin | Password verification and session issuance |
| GET `/auth/session` | Authenticated | Current user and CSRF token |
| POST `/auth/logout` | Authenticated | Session revocation |
| GET `/users` | read | Workspace assignment directory; no password/session hashes |
| POST `/users` | admin | Create user with `email`, `name`, `password`, `role` |
| POST `/users/{id}/disable` | admin | Disable another user and revoke sessions |
| GET / POST `/assets` | read / write | Inventory / asset creation |
| PUT `/assets/{id}` | write | Change category, exposure, owner and criticality; reassess risk |
| GET `/assets/{id}/report` | read | Asset-scoped metrics/history |
| GET `/imports/adapters` | read | Allowlisted adapter contracts |
| GET `/imports` | read | Last 100 import summaries |
| POST `/imports?adapter=generic-json` | write | Multipart `file`; returns job, created and duplicate counts |
| GET `/findings` | read | Search and pagination |
| GET `/findings/{id}` | read | Details, status history, activities, risk snapshots |
| PATCH `/findings/{id}` | write | Revision-checked workflow update |
| GET `/cves` | read | Local NVD mirror search |
| GET `/cves/{id}` | read | Authoritative enrichment and metadata |
| GET / PUT `/policy` | read / admin | Current thresholds / policy update and reassessment |
| GET / POST `/sync` | read / admin | Worker state / queue sync |
| GET `/dashboard` | read | Database-derived posture, aging, trends and performance |
| GET `/reports/export` | read | Audit-recorded CSV export; optional `asset_id` |
| GET `/notifications` | read | Last 50 workspace-wide in-app notifications |
| GET `/audit` | audit | Paginated audit events, 100 per page |

## Queries

`/findings`: `q` (literal, escaped text search), `status`, `severity_level` (`critical/high/medium/low/none/unknown`), `asset_id`, `assignee_id`, `overdue`, `page` (1+), `page_size` (1–100, default 50). Returns `{items,total,page,page_size}`, sorted highest custom priority first. `/cves` takes `q` and `page` (50 per page). `/audit` takes `page`. Filters are composed on the server, not just the currently visible page.

## Remediation

```json
{
  "revision": 1,
  "status": "in_progress",
  "assignee_id": 2,
  "due_at": "2026-12-01T23:59:00Z",
  "kind": "note",
  "note": "Assigned under approved change SEC-42"
}
```

`revision` and nonempty `note` are required. Omitted deadline/assignee leaves it unchanged; explicit null clears it. Assignees must be active administrators/analysts. Updates append a remediation activity, audit event and risk assessment. Revision mismatch or a simultaneous SQLAlchemy version conflict returns 409.

Allowed transitions:

```text
open        -> in_progress | accepted
in_progress -> open | mitigated | accepted
mitigated   -> in_progress | verified | accepted
verified    -> open
accepted    -> open
```

Mitigation requires `kind=mitigation`; verification requires `kind=verification`. Both require recorded notes. Only administrators accept risk. Verification is an attestation, not an automatic scan. Reimport after verification reopens the finding. `mitigated` remains active until verified. `accepted` is separately reported and excluded from active risk, not counted as remediated.

Dates are stored as UTC; response timestamps without offsets are defined as UTC, while input deadlines must include an offset. The UI displays localized dates and labels deadline edits as UTC.

## Errors and limits

401 unauthenticated; 403 wrong Origin/CSRF/permission; 404 missing record; 409 concurrent/relationship/state conflict; 413 request too large; 422 invalid schema/import/evidence; 429 throttling (`Retry-After` on request/login buckets); 500 safe error plus request ID. File parsing and unknown-asset failures retain safe failed-job metadata. Raw SQL, tokens and raw import values are never returned in validation errors.

API rate limits are 300 requests/minute per valid session user, or per direct source IP for anonymous callers. Login is independently limited to 10/minute per account and direct source IP. Production Nginx also applies per-client edge limits. Proxy trust and shared-IP behavior are documented in the security model.
