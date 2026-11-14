# Changelog

All notable changes to VulnWatch are documented here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- Permanent engineering workflow in `AGENTS.md`.
- Contribution guide, pull request template, issue templates, changelog policy, and Architecture Decision Records.
- CI concurrency controls to cancel superseded runs.
- Public GitHub Project board with Backlog, Ready, In Progress, In Review, Testing, and Done columns, linked from the README.
- Corrected repository and project-board URLs after the GitHub account rename to `JN-Schell`.

### Fixed

- Import submission no longer shares the background-refresh busy flag, so a data reload cannot disable the import button between a click's actionability check and dispatch. The malicious-import browser test waits for the import response before asserting rejection.

### Changed

- Documentation now distinguishes engineering self-review from independent human approval.
- Validation record reconciled with the hosted CI run, merged governance pull request, branch protection, repository security settings, and current test counts.

## [0.1.0] - 2026-11-13

### Added

- Normalized PostgreSQL schema with Alembic migrations, foreign keys, indexes, check constraints, and integrity tests.
- Argon2 password hashing, server-side revocable sessions, CSRF and Origin enforcement, role-based access control, database-backed rate limits, audit events, and secure error handling.
- NVD API 2.0 ingestion with CVSS v2/v3/v4 interpretation, pagination, bounded retries, persisted synchronization watermark, advisory-lock coordination, and scheduled worker.
- Asset inventory with categories, criticality, and exposure context.
- Strict Generic JSON and Generic CSV import adapters with documented schemas, atomic batches, cross-scanner CVE deduplication, observation history, and malicious-input rejection.
- Configurable custom risk prioritization that keeps CVSS and the project's priority score explicitly separate.
- Remediation assignments, deadlines, notes, mitigation and verification evidence, enforced transitions, optimistic concurrency, reopening, and overdue detection.
- Dashboard metrics, risk trends, aging and performance reports, asset-level reports, notifications, and spreadsheet-safe CSV export.
- Responsive React and TypeScript security operations interface with light and dark themes and accessible dialogs.
- Pytest API/integrity/security coverage, Playwright browser workflows, Ruff, Prettier, TypeScript checking, and production builds.
- Docker Compose deployment, GitHub Actions validation, dependency audit workflows, and tagged image publication with provenance and SBOM metadata.
- Architecture, ERD, API, import, NVD, security, threat-model, roadmap, and validation documentation.
- Synthetic demonstration seed, sample scan files, and application screenshots.

### Security

- Uploaded files are bounded, parsed in memory, never executed, and never written to disk.
- Imported descriptions are rendered as text; untrusted HTML and reference URLs are not executed or followed.
- Production configuration fails closed when trusted origins are not HTTPS.
- Demo seeding is restricted to development and test environments with an empty finding inventory.

[Unreleased]: https://github.com/JN-Schell/VulnWatch/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/JN-Schell/VulnWatch/releases/tag/v0.1.0
