# Accessibility

VulnWatch targets WCAG 2.1 AA for the critical operator workflows. Automated checks are regression coverage and do not by themselves certify conformance.

## Automated coverage

[`frontend/tests/accessibility.spec.ts`](../frontend/tests/accessibility.spec.ts) runs axe-core through Playwright with the `wcag2a`, `wcag2aa`, `wcag21a`, and `wcag21aa` tags. It covers:

- the login screen;
- overview, vulnerability inventory, assets, remediation, imports, CVE intelligence, reports, and settings in the dark theme;
- the finding and remediation dialog in dark and light themes;
- the overview in the light theme;
- keyboard-only navigation, skip-link focus, dialog opening, and focus return to the triggering finding;
- the risk-trajectory chart's accessible name and hidden text summary.

The browser fixture creates a uniquely named synthetic asset and imports the repository's sample finding payload. It never uses production data.

Run the focused checks with retries disabled:

```sh
cd frontend
E2E_PASSWORD='<test-only password>' npx playwright test tests/accessibility.spec.ts --retries=0
```

Run the complete browser suite:

```sh
cd frontend
E2E_PASSWORD='<test-only password>' npx playwright test --retries=0
```

The required CI `browser` job runs the complete Playwright suite. The `accessibility` project pins retries to **0**; the workflow project keeps the repository's existing one-retry policy for browser infrastructure failures. The accessibility spec passed **9/9** across three sequential local runs with `--retries=0`, and the full suite passed **5/5** on three consecutive fresh-database runs with `--retries=0`.

The browser suite is designed to stay within the application's 300-request-per-minute API limit. Navigation refreshes dashboard and findings only; reference data is loaded once per session and refreshed on explicit refresh or mutation. A shared Playwright fixture fails any test that receives a `429`, so stale pages and later timeouts are reported as a request-budget failure. The three consecutive full-suite runs observed a maximum rate bucket of **128/300**. The limiter is never disabled, raised, or reset by the tests.

## Manual review

Axe cannot validate every accessibility requirement. Before a release that changes layout, charts, navigation, or dialogs, review:

- [ ] 200% browser zoom does not clip controls or hide essential text.
- [ ] A keyboard-only path works through login, overview, finding details, remediation update, dialog close, and sign-out; focus is always visible and returns to the trigger.
- [ ] A screen-reader smoke test (VoiceOver or NVDA) confirms the chart summary and dialog titles are announced.
- [ ] Light and dark themes preserve text, focus-ring, chart-grid, and control-edge contrast.
- [ ] The reduced-motion preference does not hide required state changes.
- [ ] Form and API errors are announced through the existing alert regions and remain recoverable.

## Known exceptions

None at this time.

Any future axe-rule suppression must include the rule ID, affected selector, owner, rationale, and a follow-up issue. Suppress the specific selector rather than disabling a rule globally.

## Dependency note

`@axe-core/playwright` and `axe-core` are development-only dependencies licensed under MPL-2.0. They are not bundled into the production frontend.
