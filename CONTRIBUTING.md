# Contributing to VulnWatch

VulnWatch is a defensive vulnerability management application. Contributions must preserve its security properties and its evidence-based approach to vulnerability data.

Read [`AGENTS.md`](AGENTS.md) before starting. It defines the mandatory issue, branch, pull request, review, testing, and merge workflow.

## Before you start

1. Read `AGENTS.md`, `SECURITY.md`, and the relevant documentation in `docs/`.
2. Check open GitHub issues and pull requests.
3. Find or create an issue that describes the change, its acceptance criteria, and its testing requirements.
4. Wait for the issue to be labeled `Ready` before beginning substantial work.
5. Create a short-lived branch named after the issue.

Do not commit directly to `main`.

## Development setup

Requirements: Python 3.11+, [`uv`](https://docs.astral.sh/uv/), Node 22+, and PostgreSQL 16+.

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

Use synthetic data only. Never commit real scanner output, credentials, organization names, or private vulnerability details.

## Coding standards

### Python

- Follow the existing FastAPI, SQLAlchemy 2, and Pydantic patterns.
- Keep authorization checks on the server and use the existing `require(...)` dependencies.
- Validate and bound all untrusted input.
- Use parameterized queries and ORM constructs; never interpolate user input into SQL.
- Add or update Alembic migrations for schema changes. Never edit an applied migration.
- Run `uv run ruff check app tests migrations` and `uv run ruff format app tests migrations`.

### TypeScript and React

- Keep types explicit; avoid `any` unless unavoidable and documented.
- Render imported text as text. Never use untrusted HTML or URLs.
- Preserve accessible labels, keyboard behavior, and light/dark theme support.
- Run `npm run build` and `npx prettier --write src tests *.ts`.

### imports and external data

- Treat every uploaded file and every NVD response as hostile input.
- Bound file size, row count, nesting, and field lengths.
- Reject unknown fields where the schema is strict.
- Never execute, evaluate, or persist uploaded files to disk.
- Do not follow untrusted reference URLs server-side.
- Add malformed and malicious fixtures for new parsing paths.

## Tests

All changes require tests. The baseline gate is documented in `AGENTS.md`.

```sh
cd backend
uv run pytest -q
TEST_DATABASE_URL='postgresql+psycopg://USER:PASSWORD@localhost:5432/vulnwatch_test' uv run pytest -q

cd ../frontend
npm run build
npx prettier --check src tests *.ts
```

Browser tests need a disposable E2E database and an administrator; see the README. Do not point them at data you need to keep.

## Commits and pull requests

Use Conventional Commits:

```text
feat(remediation): support verification evidence
fix(auth): revoke sessions when a user is disabled
security(imports): reject control bytes in filenames
docs(threat-model): document evidence upload risks
```

Open a pull request against `main` using the repository template. Include:

- Linked issue.
- What changed and why.
- Security and data-handling implications.
- Tests run and their results.
- Migration and rollout notes.
- Screenshots for UI changes.
- Known limitations.

Keep the branch up to date and address review findings. A pull request may be squash-merged only after required checks pass and the definition of done in `AGENTS.md` is satisfied.

## Reporting security issues

Do not open a public issue for a vulnerability in VulnWatch. Follow [`SECURITY.md`](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the MIT License.
