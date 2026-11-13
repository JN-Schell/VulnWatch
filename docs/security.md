# Security model

## Supported boundary

This is a single-organization defensive inventory application. A reader can see the whole organization's assets, findings, user assignment directory and notifications. Roles are not tenant boundaries or per-asset ACLs. Deploy an instance/database per organization. Do not expose a development server publicly.

## Authentication and authorization

- Argon2 password hashes via pwdlib; 14–128 character administrator/user passwords. No public registration or default account. Passwords are never logged or returned. Unknown accounts use a dummy hash to reduce timing differences.
- Random 256-bit opaque session tokens; only SHA-256 digests persist. HttpOnly/SameSite=Strict cookies, path `/api`, absolute expiry, Secure in production. Page reload recovers a per-session CSRF token; no auth token lives in localStorage. Theme preference is the only localStorage value.
- Every write verifies an exact configured Origin and authenticated writes also use constant-time CSRF-token comparison. Login accepts JSON with a trusted Origin; wildcard CORS is not enabled.
- `admin`: read/write/admin/audit. `analyst`: read/write. `viewer`: read. API dependencies enforce permission on every route, independently of UI controls. Risk acceptance is administrator-only. Assignment disallows inactive/viewer accounts.
- Logout, disable and operator password reset revoke sessions. No browser password-reset/email flow, MFA or IdP integration is claimed. CLI reset requires host/container administrative access.

## Input and output controls

- Pydantic bounded schemas reject unknown fields and invalid/non-finite scores. SQLAlchemy parameterizes queries; literal search escapes wildcard characters. DB foreign keys, uniqueness and check constraints protect core invariants.
- Strict allowlisted JSON/CSV imports are parsed in memory, bounded to 2 MiB file content and 1,000 findings. The multipart receive path is also bounded, including chunked requests. Spooling threshold exceeds the body budget, preventing uploads from being written to disk. Nginx independently enforces a request-size limit.
- No uploaded file execution, command construction, archives, scanner execution, user-supplied outbound endpoints, or reference URL fetching. Scanner data is untrusted even after successful parsing. React renders descriptions as text; no `dangerouslySetInnerHTML`. NVD reference links require HTTP(S) and use `noopener noreferrer`.
- CSV exports neutralize spreadsheet formula-leading content. Content-Disposition uses a fixed filename. No user-controlled filesystem paths are used.
- Structured errors omit raw validation inputs and DB/external transport internals. Unexpected errors receive a request ID and are logged server-side. Treat logs as sensitive because tracebacks can contain operational metadata.

## Rate limiting and proxies

Database-backed upsert buckets enforce per-user/anonymous-source request limits and per-account/direct-IP login limits across API replicas. Nginx separately limits real edge client addresses (5 requests/second API, 10 logins/minute, bounded bursts). Headers claiming client addresses are stripped and Uvicorn proxy headers are disabled by default.

In the default Compose topology, the API sees the proxy's direct IP for login/anonymous buckets; those backend IP budgets are therefore shared across the deployment. This is conservative but can cause a small-team denial of service after repeated failed logins. Do not casually trust `X-Forwarded-For`. For a larger deployment, configure authenticated proxy trust/IP extraction for your exact network and tune budgets, with spoofing tests. Account-based login limits remain useful regardless of the edge. Rate limits are not a complete DDoS defense.

## Audit and sensitive inventory

Login successes/failures, user administration, imports (success/failure), asset changes, policy changes, remediation updates, sync windows and exports generate audit events. Finding history and remediation activity are additive through the API; no delete route exists. DB administrators can still alter records: **the audit trail is not cryptographically tamper-proof**. Export it to a restricted append-only log system for stronger assurance. There is no notification read state or email channel; alerts are workspace-wide and persistent.

## Production hardening checklist

1. Use TLS and `ENVIRONMENT=production`; startup rejects non-HTTPS trusted origins. Configure only exact hosts/origins, not wildcards. Terminate TLS at your trusted gateway and keep the Compose endpoint loopback/private. Enable HSTS at the outer gateway as well.
2. Generate unique DB credentials, NVD keys and human passwords. Inject with a secret manager; never build secrets into images or `VITE_*` variables. Rotate credentials and revoke sessions after incidents. Protect `.env` permissions during local use.
3. Use separate migration-owner and restricted runtime DB roles where possible. Compose uses one local-evaluation DB role and does not implement automatic privilege separation.
4. Keep database/API private, apply outbound egress controls for NVD, and do not share a database across untrusted organizations. Containers run as non-root with dropped capabilities, no-new-privileges, read-only roots and temporary runtime mounts.
5. Back up the DB with encryption/access controls; test restore, retention and migration rollback procedures. Monitor sync errors, API failures, throttling and disk usage. Notifications need a running worker to generate overdue events.
6. Review dependency/image updates and CI audit output. The repository is not an independent penetration-test attestation or security certification.
7. Before larger-team exposure, prioritize MFA/SSO, password self-service, session/device management, row/report scale limits and audit export. Synchronous reports currently enumerate inventory/history in memory: suitable for a small team, not unbounded enterprise ingestion.

Frontend CSP permits inline **styles** for data-driven charts, but not inline scripts, remote scripts, frames or third-party assets. API responses use `default-src 'none'`, no-store, anti-framing and nosniff headers. Production API emits HSTS. Nginx applies equivalent UI protections. These are defense in depth, not a replacement for authorization and safe rendering.
