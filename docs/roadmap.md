# Development roadmap

## Delivered baseline

Normalized PostgreSQL schema and Alembic migration; Argon2/session RBAC; actual NVD ingestion/worker; documented strict JSON/CSV adapters; assets/deduplicated findings; custom risk and threshold policy; assignment/evidence/verification lifecycle; dashboard/aging/trends/performance; CSV and asset reports; in-app notifications; responsive themes; automated API/browser tests; Docker and CI.

## Next: operational maturity

- OIDC/SSO + MFA, secure user password self-service, forced initial password change, session/device inventory.
- Independent verification/approval option, expiring risk acceptance and evidence attachments with quarantine/object storage.
- Email/webhook notifications, recipient routing, acknowledgments and alert lifecycle.
- External append-only audit sink, retention jobs and encrypted backup/restore automation.
- Vendor-specific scanner adapters with recorded export fixtures and license review.
- NVD page staging/checkpointing, explicit backfill operator command, queue metrics and better long-run heartbeat UI.

## Later: scale and advanced context

- Aggregate reporting in SQL/materialized daily snapshots, bounded history, async export streaming and worker pools.
- Full CPE applicability evaluation, EPSS/CISA KEV context (clearly sourced and separately labeled), CVSS metric chooser and score provenance history.
- Formal role/permission administration and per-asset scopes. Multi-tenancy requires a dedicated design/security review, not just an organization column.
- SARIF ingestion, additional vulnerability sources, SBOM linkage and authenticated read-only integrations. Still no unauthorized active scanning/exploitation.
- Container image digest pinning/attestations, SBOM generation, independently reviewed deployment profiles and periodic security testing.
