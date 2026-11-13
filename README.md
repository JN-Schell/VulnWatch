# VulnWatch

[![Validate VulnWatch](https://github.com/JN-Schell/VulnWatch/actions/workflows/ci.yml/badge.svg)](https://github.com/JN-Schell/VulnWatch/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Know your exposure. Own your response.**

A defensive vulnerability management application for a small IT security team. Import structured scan results, prioritize with asset context, assign remediation, record evidence, and verify outcomes. The dashboard reads the database through an authenticated API; it is not a hardcoded CVE showcase.

![Security overview with explicitly synthetic demonstration findings](docs/screenshots/overview-dark.png)

## What works

- **Inventory:** assets, categories, business criticality, internet exposure, finding search/filtering/pagination and retained observation history.
- **Imports:** documented JSON/CSV adapters, strict validation, atomic batches, cross-scanner CVE deduplication, repeat observations, and reopening after verification.
- **Intelligence:** actual NVD API 2.0 transport, CVSS v4/v3/v2 ingestion, CPE/version ranges, safe references, retries, pagination, persisted synchronization watermark and scheduled worker.
- **Risk:** configurable severity thresholds, separate custom priority, unknown-score baseline, immutable assessment snapshots, aging and recorded risk trends.
- **Remediation:** assignments, UTC deadlines, notes, mitigation/verification evidence, server-enforced transitions, optimistic concurrency and overdue detection.
- **Reporting:** live posture metrics, asset-level reports, current-assignee performance, CSV exports with spreadsheet formula neutralization, and in-app notifications.
- **Security:** Argon2 passwords, revocable server-side sessions, CSRF + Origin checks, RBAC, database-backed rate limits, bounded uploads, audit events, safe errors and production HTTPS enforcement.
- **Interface:** responsive React/TypeScript UI with light/dark themes, accessible labels, keyboard dialogs, empty/error/loading states and no HTML rendering of imported descriptions.

**Scope:** one organization per deployment. No scanning, exploitation, intrusive network activity, tenant isolation claims, SSO/MFA, email delivery, or commercial scanner API connectors. Generic adapters accept exported files; additional adapters can be implemented without changing persistence logic.

## Stack

React 19 · TypeScript · Vite · Tailwind CSS 4 · FastAPI · SQLAlchemy · Alembic · PostgreSQL 16 · Docker Compose · Pytest · Playwright · GitHub Actions.

Python dependency versions are locked in `backend/uv.lock`; frontend versions in `frontend/package-lock.json`. Python 3.11+ is supported; containers use Python 3.12 and Node 22.

## Start with Docker

Requirements: Docker Engine/Desktop with the Compose plugin. These commands run from the repository root.

```sh
cp .env.example .env
# Edit .env: replace POSTGRES_PASSWORD with a long random URL-safe value.
docker compose up --build -d
docker compose run --rm api python -m app.cli create-admin --email you@example.com --name "Your Name"
```

Open **http://localhost:8080** and use the account you created. The CLI prompts privately for a 14+ character password. There are **no default accounts or passwords**. Do not publish this development-mode HTTP endpoint to the internet.

Migrations and role/policy bootstrap run once in the `migrate` service before API/worker startup. PostgreSQL and the API are not published to host ports. Database state persists in `postgres_data`.

### First real workflow

1. Add an asset named `server-01` in **Assets**. Set its owner, criticality and exposure.
2. Import `samples/generic.json` or `samples/generic.csv` using the corresponding adapter. These are examples, not evidence of an actual scan.
3. Reimport the same file: the two findings are observed again, not duplicated.
4. Open a finding, assign it, add a UTC deadline, and move it to **In progress**.
5. Document mitigation evidence to move it to **Mitigated**; document verification evidence to move it to **Verified**.
6. Inspect the finding history, asset report, dashboard metrics, and CSV export.
7. The worker synchronizes NVD automatically. Check **CVE intelligence** for status/errors. Initial data can take several minutes; an NVD outage is shown, not replaced with fake data.

### Optional portfolio demonstration

```sh
docker compose run --rm api python -m app.cli seed-demo
```

This is allowed only in development/test mode and an empty finding inventory. It adds six assets and twelve **explicitly synthetic, non-CVE findings**. It does not create an account, contact a scanner, invent NVD results, or mark the NVD integration connected. Every description identifies the fixture as synthetic. The UI displays a demo-data warning. Screenshots use this fixture. Real NVD results remain separate.

![Asset inventory](docs/screenshots/assets.png)
![Light theme](docs/screenshots/overview-light.png)

## Local development

Requirements: `uv`, Node 22+, and PostgreSQL 16+ with a UTF-8 database. Run the API and frontend in separate terminals.

```sh
cd backend
uv sync --frozen
export ENVIRONMENT=development
export DATABASE_URL='postgresql+psycopg://USER:PASSWORD@localhost:5432/vulnwatch'
export TRUSTED_ORIGINS='["http://localhost:5173","http://127.0.0.1:5173"]'
uv run alembic upgrade head
uv run python -m app.cli create-admin --email you@example.com
uv run uvicorn app.api:app --reload --host 127.0.0.1 --port 8000
```

```sh
cd frontend
npm ci
npm run dev
```

Vite proxies `/api` to port 8000. In a third terminal, with the same backend environment, run `uv run python -m app.worker`. Use `uv run python -m app.cli sync` for a one-shot administrative sync; avoid concurrent manual NVD clients sharing a public egress IP.

For an offline UI-only preview, explicitly set `DATABASE_URL=sqlite:///./local.db` in development mode and run migrations/bootstrap. **SQLite is not the supported production database or a substitute for PostgreSQL integration tests.**

## Configuration

| Setting | Purpose |
| --- | --- |
| `DATABASE_URL` | SQLAlchemy PostgreSQL DSN; local development only, Compose constructs it from its database settings |
| `POSTGRES_PASSWORD` | Compose DB credential; URL-safe characters required for the interpolated DSN |
| `ENVIRONMENT` | `development`, `test`, or `production`; default is production, which requires HTTPS origins |
| `TRUSTED_ORIGINS` | JSON array of exact browser origins, including scheme and port |
| `ALLOWED_HOSTS` | JSON array of HTTP hostnames; include your deployed hostname and internal healthcheck names |
| `SESSION_HOURS` | Absolute session lifetime, 1–168; default 12 |
| `NVD_API_KEY` | Optional NVD key, sent only in an HTTP header to the fixed NVD endpoint |
| `NVD_INITIAL_DAYS` | Initial modified-date window, 1–120; default 30; this is not a complete NVD mirror |
| `SYNC_INTERVAL_SECONDS` | At least 7200 seconds (two hours) |

`.env` is ignored by Git and Docker build context. Never commit real credentials or put NVD keys in frontend variables. Use your deployment's secret manager to inject environment values in production. Compose's `.env` workflow is for local evaluation, not a claim of enterprise secret management.

## Tests and quality gates

```sh
cd backend
uv run pytest -q --cov=app
uv run ruff check app tests migrations
uv run ruff format --check app tests migrations
ENVIRONMENT=test DATABASE_URL=sqlite:////tmp/vulnwatch-migration-check.db uv run alembic upgrade head
ENVIRONMENT=test DATABASE_URL=sqlite:////tmp/vulnwatch-migration-check.db uv run alembic check
```

The default test database is disposable SQLite. To run the same API/integrity suite on PostgreSQL:

```sh
TEST_DATABASE_URL='postgresql+psycopg://USER:PASSWORD@localhost/vulnwatch_test' uv run pytest -q
```

**This drops/recreates application tables. Use only a dedicated disposable database containing `vulnwatch_test` in its name.** Tests use NVD fixture transports, including failures, pagination, and timeouts; they do not consume the live NVD rate limit.

### Browser workflow tests

Prepare a **separate empty E2E database**; do not point browser tests at an inventory you need to keep. From `backend`, export development `ENVIRONMENT`, its `DATABASE_URL`, `ALLOWED_HOSTS='["localhost","127.0.0.1"]'`, and `TRUSTED_ORIGINS='["http://127.0.0.1:5173"]'`. Export `E2E_PASSWORD` to a chosen test-only 14+ character password. Then:

```sh
uv run alembic upgrade head
VULNWATCH_ADMIN_PASSWORD="$E2E_PASSWORD" uv run python -m app.cli create-admin
cd ../frontend
npm ci
npx playwright install chromium
npm run test:e2e
npm run build
```

The Playwright config starts the API and Vite using those environment values. It tests a real import/deduplication/remediation/export workflow, malicious import rejection, persistent themes, mobile navigation, and logout against the actual backend. Repeat runs require a fresh E2E database. CI runs the backend suite on SQLite and PostgreSQL, browser tests on PostgreSQL, dependency audits, and a Compose image/startup smoke test.

If development ports are already in use, set `E2E_API_PORT=8001 E2E_WEB_PORT=5174` and include `http://127.0.0.1:5174` in `TRUSTED_ORIGINS`. This starts isolated test servers rather than reusing your development database.

## Architecture and documentation

- [Architecture, ERD, invariants, and phased acceptance gates](docs/architecture.md)
- [Architecture Decision Records](docs/adr/README.md)
- [Import schemas and adapter extension guide](docs/imports.md)
- [NVD synchronization and external API limitations](docs/nvd.md)
- [API reference and authentication examples](docs/api.md)
- [Security model and deployment hardening](docs/security.md)
- [Threat model](docs/threat-model.md)
- [Development roadmap](docs/roadmap.md)
- [Validation record and known limitations](docs/validation.md)

## Project governance

Development is tracked through GitHub Issues, milestones, and the repository project board. Every meaningful change has an issue, a short-lived branch, a pull request, a documented engineering self-review, required CI checks, and a squash merge to `main`.

- [Engineering instructions and definition of done](AGENTS.md)
- [Contributing guide](CONTRIBUTING.md)
- [Changelog](CHANGELOG.md)
- [Project board](https://github.com/users/JN-Schell/projects/1)
- [Issues](https://github.com/JN-Schell/VulnWatch/issues)
- [Milestones](https://github.com/JN-Schell/VulnWatch/milestones)
- [Pull requests](https://github.com/JN-Schell/VulnWatch/pulls)

The maintainer merges their own pull requests after self-review because this is a solo-maintainer portfolio repository. That self-review is not represented as independent human approval.

Interactive schema consumers can retrieve the authenticated `/api/openapi.json`. No unauthenticated API explorer is exposed. Architecture/ERD diagrams are Mermaid and render directly on GitHub.

Version tags (`v*`) trigger a GitHub Actions workflow that publishes API/web images to GHCR with build provenance and SBOM metadata. Tag only a commit whose validation jobs passed. Deployment remains an explicit operator decision; no workflow has access to a production host or production secrets.

## Operations

- `docker compose logs api worker migrate` to inspect health and sync failures.
- `docker compose run --rm api python -m app.cli reset-password --email you@example.com` resets a password and revokes that user's sessions. Account disabling also revokes sessions. Administrators cannot disable themselves.
- Back up PostgreSQL using `pg_dump` and regularly verify a restore to a separate environment. Protect backups as sensitive security inventory. Upgrade with a tested backup, then let the migration service apply the new revision.
- Worker cleanup deletes expired sessions and old rate buckets. Audit/import/finding histories are retained; establish retention/export procedures before long-term deployment.
- `docker compose down` preserves the volume. `docker compose down -v` irreversibly deletes it.
- For production: terminate TLS at a trusted reverse proxy, bind the Compose web port privately, set `ENVIRONMENT=production`, exact HTTPS `TRUSTED_ORIGINS`/`ALLOWED_HOSTS`, managed secrets, least-privilege DB credentials and monitored backups. See the hardening checklist, especially reverse-proxy login throttling.

## License and data attribution

MIT for application code. NVD content is attributed to the National Institute of Standards and Technology; this product is not endorsed or certified by NIST. NVD enrichment and scanner observations are evidence inputs, not proof that an asset is exploitable or remediated. Validate affected versions and verification evidence with your own authorized security process.
