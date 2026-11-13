# Threat model

## Assets and actors

Protect passwords/session tokens, vulnerability/asset inventory, remediation evidence, NVD API key, import integrity, audit history, and database availability. Actors: anonymous internet clients, authenticated viewers, analysts, administrators, compromised scanners/import files, compromised upstream NVD content, and deployment/DB operators. Host/DB administrators are trusted with the organization's full inventory; defending against them requires external controls.

## Data flows

Browser → same-origin reverse proxy → authenticated API → database. Uploaded data → bounded parser → validated canonical records → transactional database write. Worker → fixed NVD HTTPS endpoint → ingestion validation → database enrichment. Database → reports/exports → human readers/spreadsheet tools. See architecture diagram and ERD.

| Threat | Mitigation | Residual risk / follow-up |
| --- | --- | --- |
| Credential stuffing / enumeration | Argon2, dummy hash, account/IP throttles, generic errors, no public registration | No MFA/SSO; shared source throttling can deny legitimate logins |
| Session theft/fixation | Fresh random token, digest-at-rest, HttpOnly/Secure/Strict cookie, absolute expiry, revocation | Browser/host compromise remains out of scope; no device inventory |
| CSRF / login CSRF | Exact Origin, JSON login, session CSRF header on writes, SameSite | XSS can act as user; avoid widening origins |
| Vertical privilege escalation | Server-side permission dependencies, admin-only policy/users/audit/risk acceptance | Single-org readers intentionally see whole inventory |
| SQL injection / object reference abuse | Parameterized queries, permission checks, typed identifiers, no multi-tenant promises | A reader is authorized for every asset in this deployment |
| Stored XSS / malicious references | React text rendering, no HTML insertion, HTTP(S)-only links, CSP | Malicious but valid external sites remain possible; users must assess references |
| Executable uploads / path traversal | No execution/extraction, extension allowlist, in-memory parsing, filename basename only | No antivirus claim; stored text may still contain misleading instructions |
| Parser bombs / huge body / chunked bypass | Byte/row/depth safeguards, bounded receive, no archive parsers, edge size/time limits | JSON is parsed in-process; hostile concurrent requests still consume bounded resources |
| Duplicate poisoning / partial import | Canonical identities, uniqueness, existing-asset requirement, all-or-nothing write, retained failures | Scanner identity/locator normalization must be agreed across adapters |
| Lost remediation updates | Required revision + SQLAlchemy version column, transition validation, preserved history | Independent verification attestations are trusted human input |
| Fake verification / malicious risk acceptance | Evidence type/nonempty notes, authorized writer, administrator risk acceptance, audit | No two-person approval or automatic evidence validation |
| CVSS/priority confusion | Separate fields/labels, source provenance, unknown remains null, documented formula | Scanner-provided scores may be wrong until authoritative enrichment |
| Upstream outage / bad synchronization | Fixed TLS endpoint, timeouts, bounded retries, pagination validation, transaction/cursor, advisory lock | NVD data can lag; large windows can hold transactions; no alternate source |
| SSRF / key exfiltration | No user outbound URL, no redirects, key only in fixed-host header, no reference fetch | Compromised app host or DNS/TLS trust can expose credentials |
| CSV formula injection | Prefix formula-like fields with apostrophe, CSV writer quoting | Spreadsheet consumers vary; treat exports as sensitive untrusted data |
| Audit repudiation / DB compromise | Additive API history, audit on security actions, no deletion endpoints | DB owner can tamper; use external append-only audit storage |
| Availability / resource exhaustion | Edge + persisted API throttles, bounded upload, pagination, cleanup | Reports and history queries are small-team scoped, not enterprise scale |
| Secret leakage / insecure deployment | No default user, ignored env files, production HTTPS validation, non-root/private services | Local Compose credentials need stronger production secret management |
| Dependency/supply-chain compromise | Lockfiles, automated tests, dependency audits, image build smoke job | Base image references use maintained tags, not immutable digests; review/pin before production |

## Validation and review scope

Pytest covers authentication/permissions, CSRF/origin, expiry, throttling, FK/check integrity, duplicate/atomic imports, malformed/malicious input, custom risk/CVSS semantics, lifecycle/concurrency, safe exports, NVD failures/pagination and cursor behavior. Playwright exercises the actual backend, not mocked dashboards. This model is an engineering review, not a certified audit. Track remaining items in the roadmap.
