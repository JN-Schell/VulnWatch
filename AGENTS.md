# VulnWatch engineering instructions

This file is the permanent operating agreement for every human or AI contributor working in this repository. Read it at the start of every development session. If another agent instruction file exists, it must not contradict this document.

Repository: `sch3lly-stack/VulnWatch`  
Default branch: `main`  
License: MIT  
Maintainer model: solo maintainer with autonomous AI assistance

## Session-start checklist

Before doing any development work:

1. Read this file.
2. Inspect `git status`, the current branch, and recent commits.
3. Inspect the GitHub repository, open issues, open pull requests, and failing checks.
4. Review the current milestone and project board state.
5. Select the next task by priority, dependency order, and roadmap phase.
6. Never rely on conversation history as the source of project status.

If GitHub access is unavailable, continue only with work that is safe to perform locally, and report exactly what could not be synchronized.

## GitHub is authoritative

GitHub Issues are the authoritative source of project work.

- Never begin a meaningful feature, bug fix, refactor, security change, infrastructure change, or documentation task without an associated issue.
- Every issue must include: objective, background, scope, acceptance criteria, dependencies, testing requirements, priority, labels, and a definition of done.
- Use the repository's issue templates and consistent labels.
- Group related issues into milestones and the GitHub Project board.
- Reference the issue number in the branch name, commits, and pull request.
- Do not create duplicate issues. Search first and update an existing issue when appropriate.
- Do not close an issue until its acceptance criteria are met, tests pass, the pull request is merged, and the resulting `main` branch is verified.
- Completed work discovered before tracking existed must be recorded honestly as retroactive: state that it predates the issue, link the baseline commit, and do not invent a historical pull request or review.

## Labels, milestones, and project board

Required type labels:

- `type:feature`
- `type:bug`
- `type:refactor`
- `type:security`
- `type:documentation`
- `type:testing`
- `type:infrastructure`

Required priority labels:

- `priority:critical`
- `priority:high`
- `priority:medium`
- `priority:low`

Additional labels:

- `status:blocked`
- `area:backend`
- `area:frontend`
- `area:database`
- `area:ci-cd`
- `area:docs`

Project board columns:

1. **Backlog** — approved future work.
2. **Ready** — requirements and acceptance criteria defined.
3. **In Progress** — active development.
4. **In Review** — pull request open and under self-review.
5. **Testing** — validation and CI running or being investigated.
6. **Done** — merged and verified on `main`.

Milestones represent meaningful releases or roadmap phases. Do not place unrelated work in a milestone merely to reduce its size.

## Branching

Never commit directly to `main`. Use short-lived, focused branches:

- `feature/<issue>-<description>`
- `bugfix/<issue>-<description>`
- `hotfix/<issue>-<description>`
- `refactor/<issue>-<description>`
- `security/<issue>-<description>`
- `docs/<issue>-<description>`
- `test/<issue>-<description>`

Examples:

```text
feature/24-sso-mfa
bugfix/31-playwright-import-race
security/42-code-scanning
docs/50-threat-model-update
```

Keep one logical change per branch. Do not combine unrelated work to reduce pull request count.

## Commits

Use Conventional Commits and the imperative mood:

```text
feat(auth): add session revocation
fix(imports): reject NUL bytes in upload names
test(e2e): remove submit race from malicious import test
docs(governance): define engineering workflow
ci: add CodeQL analysis
```

Commits must be meaningful, buildable where practical, and free of secrets or generated artifacts.

## Pull requests

Every meaningful change goes through a pull request that:

- References its issue with `Closes #<number>` or `Relates to #<number>`.
- Explains what changed and why.
- Summarizes implementation and affected components.
- Lists tests and validation performed, with exact commands.
- Documents risks, rollout notes, and migration notes when applicable.
- Includes screenshots or recordings for significant UI changes.
- Passes all required CI checks.
- Contains no unrelated changes.

Use the repository pull request template. Keep pull requests reviewable.

## Engineering self-review

The maintainer may autonomously review, correct, and merge their own pull requests. This is an **engineering self-review**, not independent human approval.

For every pull request:

1. Read the complete diff.
2. Verify every acceptance criterion.
3. Look for unintended changes and scope creep.
4. Review authentication, authorization, input validation, data exposure, and injection risks.
5. Check for duplicated, dead, or unnecessarily complex code.
6. Verify style, typing, and documentation.
7. Run all relevant tests, linters, type checks, migration checks, and production builds.
8. Verify required GitHub Actions checks pass.
9. Push corrections to the same branch and re-run validation.
10. Merge only when the definition of done is satisfied.

Never claim independent review, fake an approval, or use a second account to bypass review rules. If a repository rule requires independent approval that is unavailable, leave the pull request open and report the blocker.

## Required validation

Run the checks relevant to the change. The full baseline gate is:

```sh
cd backend
uv sync --frozen
uv run ruff check app tests migrations
uv run ruff format --check app tests migrations
uv run pytest -q
uv run pytest -q --cov=app --cov-report=term-missing
ENVIRONMENT=test DATABASE_URL=sqlite:////tmp/vulnwatch-migration-check.db uv run alembic upgrade head
ENVIRONMENT=test DATABASE_URL=sqlite:////tmp/vulnwatch-migration-check.db uv run alembic check
```

PostgreSQL integration tests:

```sh
cd backend
TEST_DATABASE_URL='postgresql+psycopg://USER:PASSWORD@HOST:PORT/vulnwatch_test' uv run pytest -q
```

`TEST_DATABASE_URL` must point to a disposable database whose name contains `vulnwatch_test`. The suite drops and recreates tables.

Frontend:

```sh
cd frontend
npm ci
npm run build
npx prettier --check src tests *.ts
```

Browser workflow tests require a separate empty E2E database, a bootstrapped administrator, and `E2E_PASSWORD`:

```sh
cd frontend
E2E_PASSWORD='<test-only password>' npm run test:e2e
```

Container and CI configuration:

```sh
docker compose config --quiet
docker compose up --build --wait web
curl --fail http://localhost:8080/api/health
```

Do not weaken, skip, or delete tests to obtain a green build. Fix the cause. If a check cannot run in the current environment, state this explicitly in the pull request and issue.

## Definition of done

A task is complete only when:

- Implementation satisfies the issue's acceptance criteria.
- Relevant tests pass, including regression coverage.
- Linters, formatters, type checks, migration checks, and production builds pass.
- Security implications have been reviewed.
- Documentation, changelog, ADRs, and environment examples are updated when needed.
- Required CI checks pass on the pull request.
- The pull request is merged into `main`.
- The merged result is verified.
- The issue is closed with a concise completion comment.
- The project board and milestone are updated.

Code written is not the same as work completed.

## Merge policy

- Prefer squash merging for focused branches.
- Required CI checks must pass.
- No unresolved blocking comments.
- No merge conflicts.
- Target branch must be `main`.
- Linear history is enforced.
- Delete the merged branch.
- Never bypass branch protection, required checks, secret scanning, or repository security settings.
- If a merge is blocked by permissions or protection, report the exact blocker and leave the pull request open.

## Repository settings policy

The intended GitHub configuration is:

- Default branch: `main`.
- Pull request required before merging.
- Required status checks: backend, browser, Compose smoke test, and CodeQL once established.
- Required approvals: **0**, because this is a solo-maintainer repository with autonomous agent work. Self-review is documented; no independent approval is claimed.
- Linear history required.
- Force pushes and branch deletion on `main` disabled.
- Squash merging enabled; merge commits and rebase merging disabled where the repository policy allows.
- Automatically delete merged branches.
- Dependabot alerts, Dependabot security updates, secret scanning, push protection, and CodeQL enabled where the plan permits.
- GitHub Actions permissions restricted to least privilege.

Repository settings are applied through the GitHub API/CLI and recorded in issues. They are not claimed unless verified.

## Security and safety boundaries

VulnWatch is a defensive vulnerability management platform.

- Never implement unauthorized scanning, exploitation, credential theft, or intrusive network activity.
- Never execute uploaded files or treat imported scan data as trusted.
- Never render imported HTML or follow untrusted URLs.
- Never commit credentials, tokens, real scan data, private vulnerability details, or production database dumps.
- Use synthetic data for tests, screenshots, and demonstrations.
- Do not disable authentication, authorization, CSRF, rate limiting, audit logging, or other security controls to make a test pass.
- Do not expose development mode, demo credentials, or seed accounts as production configuration.
- Do not perform destructive production database operations or irreversible deployments without explicit authorization.
- Report vulnerabilities through the process in `SECURITY.md`.

## External integrations and honesty

- Never hardcode or fabricate NVD results, scanner results, uptime, or CI outcomes.
- Clearly distinguish live external API behavior from fixture-based tests.
- Report external API limitations, rate limits, and synchronization behavior.
- Do not claim a GitHub issue, branch, pull request, review, merge, project update, or deployment exists unless the operation succeeded and was verified.
- Do not claim CI passed unless the checks were observed.
- Document known limitations and outstanding validation honestly.

## Documentation and releases

Keep these current:

- `README.md`
- `AGENTS.md`
- `CHANGELOG.md`
- `CONTRIBUTING.md`
- `SECURITY.md`
- `docs/architecture.md`
- `docs/api.md`
- `docs/imports.md`
- `docs/nvd.md`
- `docs/security.md`
- `docs/threat-model.md`
- `docs/roadmap.md`
- `docs/validation.md`
- Architecture Decision Records under `docs/adr/`

Use Semantic Versioning. Add a changelog entry for every meaningful release. Record architecturally significant decisions as ADRs. Tag releases only from a commit whose required checks passed.

## Maintaining this file

This file is version controlled and must remain in the repository root. Do not delete or replace it without explicit authorization. Update it when engineering procedures, repository settings, validation commands, or project conventions change. Changes to this file require a pull request and self-review like any other meaningful change.
