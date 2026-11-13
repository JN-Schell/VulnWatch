# Validation record

Local validation performed **November 13, 2026**, on macOS with Python 3.11.18, Node 26.11.0, uv 0.13.8 and a dedicated PostgreSQL 16.16 UTF-8 instance. CI separately targets Python 3.12 / Node 22 / PostgreSQL 16. Test credentials and databases were disposable, not production accounts.

## Results

| Gate | Result |
| --- | --- |
| Architecture / normalized schema | Documented in `architecture.md`; explicit Alembic revision includes tables, foreign keys, indexes and constraints |
| SQLite migration upgrade + drift check | Passed |
| PostgreSQL migration upgrade + drift check | Passed |
| PostgreSQL backend suite | **40 passed**, including advisory lock exclusivity, real optimistic concurrency, DB integrity, NVD failures, and workflow/import security |
| SQLite backend suite | **39 passed, 1 skipped**; PostgreSQL-only advisory lock test is intentionally skipped |
| Backend coverage on PostgreSQL | **89%** statement coverage; security and import services 100%, risk service 100% |
| Playwright / real PostgreSQL API | **2 passed**; import, deduplication, assignment, mitigation, verification, CSV download, mobile navigation, theme persistence, malicious input rejection and logout |
| Frontend production build | TypeScript checking and Vite production build passed |
| Ruff / Prettier | Checks passed |
| Locked production Python dependencies | `pip-audit` reported no known vulnerabilities at validation time |
| Frontend dependency audit | `npm audit` reported no known vulnerabilities at validation time |
| Compose / GitHub Actions schemas | Validated against Compose specification and GitHub workflow JSON schemas |
| Live NVD connectivity | Actual HTTPS CVE-ID request succeeded; parsed `CVE-2021-44228` from the upstream response (not a fixture) |
| Screenshots | Captured from the running application using actual database-backed sample/demo data; synthetic-data banner visible |

The live NVD smoke test is not a claim that the full initial thirty-day synchronization ran. Full-window behavior, pagination/retries and rollback are covered with labeled fixture transports. No scanner was run and no real organization was assessed.

## Outstanding validation / limits

- **Docker is not installed on the implementation machine.** Container image builds and Compose startup were not executed locally. A dedicated GitHub Actions job builds images and runs the stack/health checks, but that hosted job has not been run from this workspace. Schema validation alone does not prove container runtime behavior.
- GitHub Actions workflows are provided, not claimed as completed hosted runs. Tagged image publication has not been executed. No repository, commit, pull request, remote deployment or production secrets were created.
- The installed Starlette emits a TestClient/httpx deprecation warning. Tests pass; migrate the test transport if future Starlette versions remove compatibility. It is not suppressed.
- This is a tested functional small-team baseline, not a third-party penetration test or enterprise production certification. Review deployment hardening and roadmap items (MFA/SSO, audit export, evidence approval, streaming/scale limits) before real operational use.
- Dashboard trends show recorded assessment dates; there is no invented backfilled historical series. Demo data uses explicitly synthetic non-CVE findings, and generic examples are scanner-format illustrations, not actual scan evidence.
