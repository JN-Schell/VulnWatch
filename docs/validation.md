# Validation record

Local validation performed **November 13, 2026**, on macOS with Python 3.11.18, Node 26.11.0, uv 0.13.8 and a dedicated PostgreSQL 16.16 UTF-8 instance. Hosted validation ran in GitHub Actions on the same date with Python 3.12 / Node 22 / PostgreSQL 16. Test credentials and databases were disposable, not production accounts. Browser workflow isolation for issue #38 and accessibility coverage for issue #33 were revalidated on **November 19, 2026**. Browser request-budget stabilization for issue #56 was revalidated on **November 21, 2026**. Vendor scan adapters for issue #27 were validated on **November 21, 2026**.

Repository: <https://github.com/JN-Schell/VulnWatch>  
Baseline commit: `9b36ee9`  
Governance merge commit: `b6afa38` (pull request #2)

## Results

| Gate | Result |
| --- | --- |
| Architecture / normalized schema | Documented in `architecture.md`; explicit Alembic revision includes tables, foreign keys, indexes and constraints |
| SQLite migration upgrade + drift check | Passed |
| PostgreSQL migration upgrade + drift check | Passed |
| PostgreSQL backend suite | **68 passed**, including advisory lock exclusivity, real optimistic concurrency, DB integrity, NVD failures, workflow/import security, and the vendor adapter suite |
| SQLite backend suite | **67 passed, 1 skipped**; PostgreSQL-only advisory lock test is intentionally skipped |
| Backend coverage on PostgreSQL | **90%** statement coverage; security, imports, models, and risk service 100%, vendor adapters 94% |
| Vendor adapters (issue #27) | Trivy, Grype, and OWASP Dependency-Check JSON parsing verified against synthetic fixtures built from each tool's published JSON structure. Adapter unit tests cover mapping, missing optional fields, duplicates, namespace-qualified non-CVE identities, row/byte limits, duplicate JSON keys, non-finite numbers, control bytes, and malformed payloads. Cross-adapter deduplication and an end-to-end API import are covered, including the requirement that vendor reports name an existing target asset. No vendor SDK, scanner execution, or live scanner API was used |
| Playwright / real PostgreSQL API | **6 passed** in the current suite; import, deduplication, assignment, mitigation, verification, CSV download, mobile navigation, theme persistence, malicious input rejection, logout, and the vendor adapter target-asset flow. Issue #20's submit-timing flake was fixed by keeping background refresh off the import button's disabled state. Issue #38 gives each run a unique asset identifier and waits for the `201` asset-save response before asserting the dialog closed. Issue #33 adds axe-core scans for the login screen, critical pages, finding/remediation dialogs, both themes, keyboard focus, and the chart summary. The accessibility Playwright project requires zero retries; the workflow project retains its existing one-retry policy. The frontend loads dashboard and findings for navigation, and loads reference data (assets, users, imports, sync, notifications, policy, adapter contracts) only on first use, explicit refresh, or a mutation. A shared Playwright fixture fails any test that receives a `429`. Issue #56 revalidation: full suite **5 passed on three consecutive fresh-database runs with `--retries=0`**, with a maximum observed rate bucket of **128/300**; the 300-request-per-minute limiter stayed enabled |
| Frontend production build | TypeScript checking and Vite production build passed |
| Ruff / Prettier | Checks passed |
| Locked production Python dependencies | `pip-audit` reported no known vulnerabilities at validation time |
| Frontend dependency audit | `npm audit` reported no known vulnerabilities at validation time |
| Compose / GitHub Actions schemas | Validated against Compose specification and GitHub workflow JSON schemas |
| Hosted CI | GitHub Actions run [43524392125](https://github.com/JN-Schell/VulnWatch/actions/runs/43524392125) on commit `3ec7ffe`: `backend`, `browser`, and `compose` all succeeded |
| Branch protection | Applied and read back through the API; required checks, strict branches, linear history, conversation resolution, no force pushes/deletions, no bypass for administrators. A controlled direct push was rejected with `GH006` |
| Repository security settings | Dependabot alerts, automated security fixes, secret scanning, and push protection verified enabled; Actions restricted to GitHub-owned and verified Marketplace actions |
| Live NVD connectivity | Actual HTTPS CVE-ID request succeeded; parsed `CVE-2021-44228` from the upstream response (not a fixture) |
| Screenshots | Captured from the running application using actual database-backed sample/demo data; synthetic-data banner visible |

The live NVD smoke test is not a claim that the full initial thirty-day synchronization ran. Full-window behavior, pagination/retries and rollback are covered with labeled fixture transports. No scanner was run and no real organization was assessed.

## Outstanding validation / limits

- **Docker is not installed on the implementation machine.** Container image builds and Compose startup were not executed locally. The hosted `compose` job built the images, started the stack, and passed its health checks; local container runtime behavior remains unverified.
- Hosted CI validates the backend, browser, and Compose jobs. Tagged image publication has not been executed. No production deployment or production secret has been created.
- Browser verification uses fresh disposable databases and a request-budget-aware frontend. Three consecutive full-suite runs with `--retries=0` passed with a maximum observed rate bucket of 128/300. The application still enforces its 300-request-per-minute API limit; the tests do not bypass, reset, or disable it, and any `429` fails the test explicitly.
- No independent human code review or third-party penetration test has been performed. Merges use documented engineering self-review and required hosted checks; this is not represented as independent approval.
- The installed Starlette emits a TestClient/httpx deprecation warning. Tests pass; migrate the test transport if future Starlette versions remove compatibility. It is not suppressed.
- This is a tested functional small-team baseline, not a third-party penetration test or enterprise production certification. Review deployment hardening and roadmap items (MFA/SSO, audit export, evidence approval, streaming/scale limits) before real operational use.
- Dashboard trends show recorded assessment dates; there is no invented backfilled historical series. Demo data uses explicitly synthetic non-CVE findings, and generic examples are scanner-format illustrations, not actual scan evidence.
- Vendor adapters (Trivy, Grype, Dependency-Check) were verified against synthetic fixtures derived from each tool's published JSON structure, not against exports from a live scanner. No scanner was executed and no scanner API was contacted. Real exports may contain fields or nesting the fixtures do not cover; unknown shapes are rejected rather than guessed.
