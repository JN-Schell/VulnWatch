# Architecture Decision Records

Architecture Decision Records (ADRs) capture significant technical decisions, the context that drove them, and their consequences. They are immutable historical records: when a decision changes, add a new ADR that supersedes the old one instead of rewriting history.

| ADR | Title | Status |
| --- | --- | --- |
| [0001](0001-single-tenant-postgresql.md) | Single-organization deployment on PostgreSQL | Accepted |
| [0002](0002-separate-cvss-and-priority.md) | Keep CVSS separate from custom risk priority | Accepted |
| [0003](0003-adapter-based-imports.md) | Adapter-based, in-memory scan imports | Accepted |
| [0004](0004-server-side-sessions.md) | Server-side sessions with CSRF and Origin checks | Accepted |

New ADRs use the filename `NNNN-short-title.md` and include status, context, decision, and consequences.
