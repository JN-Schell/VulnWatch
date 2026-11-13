# 0001 — Single-organization deployment on PostgreSQL

- **Status:** Accepted
- **Date:** 2026-11-13

## Context

VulnWatch is intended for a small IT security team. A multi-tenant SaaS would require tenant isolation, per-tenant authorization, billing, and a substantially different threat model. The project must still provide reliable concurrency, constraints, migrations, and reporting.

## Decision

One VulnWatch deployment serves one organization. PostgreSQL is the production system of record. SQLite is supported only for fast isolated tests and an explicitly labeled offline preview; it is not a production database.

Separate organizations must run separate instances and databases. No application-level tenant column is claimed as isolation.

## Consequences

- Authorization and queries remain simpler and easier to review.
- Database constraints, transactions, foreign keys, and advisory locks provide strong integrity guarantees.
- Horizontal API scaling is possible because state, rate limits, sessions, and synchronization leases live in PostgreSQL.
- Cross-organization reporting is out of scope. Multi-tenancy would require a dedicated design and security review, not merely adding an organization column.
- Backup, retention, and deployment automation remain per-instance operator responsibilities.
