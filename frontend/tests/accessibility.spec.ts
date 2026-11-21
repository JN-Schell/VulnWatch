import { test, expect } from "./fixtures";
import type { Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";
import { readFileSync } from "node:fs";
import path from "node:path";

const password = process.env.E2E_PASSWORD;
if (!password)
  throw new Error(
    "Set E2E_PASSWORD for the administrator bootstrapped in the test database",
  );

const tags = ["wcag2a", "wcag2aa", "wcag21a", "wcag21aa"];

async function scan(page: Page, label: string) {
  const results = await new AxeBuilder({ page }).withTags(tags).analyze();
  const summary = results.violations
    .map(
      (violation) =>
        `${violation.id} (${violation.impact}): ${violation.help}\n${violation.nodes
          .map((node) => `  ${node.target.join(" ")}`)
          .join("\n")}`,
    )
    .join("\n\n");
  expect(results.violations, `${label}\n\n${summary}`).toEqual([]);
}

async function login(page: Page) {
  await page.goto("/");
  await page.getByLabel("Email address").fill("admin@example.com");
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in to workspace" }).click();
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible();
}

async function seedFinding(page: Page) {
  const session = await page.request.get("/api/auth/session");
  expect(session.ok()).toBeTruthy();
  const { csrf_token } = (await session.json()) as { csrf_token: string };
  const headers = {
    "X-CSRF-Token": csrf_token,
    Origin: new URL(page.url()).origin,
  };
  const assetName = `a11y-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const asset = await page.request.post("/api/assets", {
    headers,
    data: {
      name: assetName,
      category: "Server",
      criticality: 4,
      exposure: "internal",
      owner: "Accessibility",
    },
  });
  expect(asset.status()).toBe(201);

  const sample = JSON.parse(
    readFileSync(path.resolve("../samples/generic.json"), "utf8"),
  ) as { findings: Array<Record<string, unknown>> };
  const payload = {
    ...sample,
    findings: sample.findings.map((finding) => ({
      ...finding,
      asset: assetName,
    })),
  };
  const imported = await page.request.post(
    "/api/imports?adapter=generic-json",
    {
      headers,
      multipart: {
        file: {
          name: "accessibility.json",
          mimeType: "application/json",
          buffer: Buffer.from(JSON.stringify(payload)),
        },
      },
    },
  );
  expect(imported.status()).toBe(201);
  return assetName;
}

async function selectSeededFinding(page: Page, assetName: string) {
  await page.getByLabel("Asset filter").selectOption({ label: assetName });
  await page.getByLabel("Search findings").fill("Log4j");
  const finding = page.getByRole("button", {
    name: "Apache Log4j remote code execution",
    exact: true,
  });
  await expect(finding).toHaveCount(1);
  return finding;
}

test("login page has no automatically detectable WCAG A/AA violations", async ({
  page,
}) => {
  await page.goto("/");
  await expect(
    page.getByRole("heading", { name: "Welcome back" }),
  ).toBeVisible();
  await scan(page, "login page");
});

test("critical pages, dialogs, and themes have no detectable violations", async ({
  page,
}) => {
  await login(page);
  const assetName = await seedFinding(page);
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible();
  await expect(
    page.getByRole("img", {
      name: "Recorded aggregate custom risk over time",
    }),
  ).toBeVisible();
  await expect(page.locator("#risk-chart-summary")).toContainText(
    "Aggregate custom risk",
  );
  await scan(page, "overview, dark theme");

  await page.getByRole("button", { name: /^Vulnerabilities/ }).click();
  await expect(
    page.getByRole("heading", { name: "Vulnerability inventory" }),
  ).toBeVisible();
  const finding = await selectSeededFinding(page, assetName);
  await scan(page, "vulnerabilities, dark theme");

  await finding.click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await scan(page, "finding and remediation dialog, dark theme");
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).not.toBeVisible();

  await page.getByRole("button", { name: "Assets", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Assets" })).toBeVisible();
  await scan(page, "assets, dark theme");

  await page.getByRole("button", { name: "Remediation", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Remediation workspace" }),
  ).toBeVisible();
  await scan(page, "remediation, dark theme");

  await page.getByRole("button", { name: "Imports", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Import scan results" }),
  ).toBeVisible();
  await scan(page, "imports, dark theme");

  await page
    .getByRole("button", { name: "CVE intelligence", exact: true })
    .click();
  await expect(
    page.getByRole("heading", { name: "CVE intelligence" }),
  ).toBeVisible();
  await expect(page.getByLabel("Search CVE intelligence")).toBeVisible();
  await scan(page, "CVE intelligence, dark theme");

  await page.getByRole("button", { name: "Reports", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Reports", exact: true }),
  ).toBeVisible();
  await expect(
    page.getByRole("heading", { name: "Vulnerability aging" }),
  ).toBeVisible();
  await scan(page, "reports, dark theme");

  await page.getByRole("button", { name: "Settings", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Risk prioritization policy" }),
  ).toBeVisible();
  await scan(page, "settings, dark theme");

  await page.getByRole("button", { name: "Overview", exact: true }).click();
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible();
  await page.getByRole("button", { name: "Toggle theme" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await scan(page, "overview, light theme");

  await page.getByRole("button", { name: /^Vulnerabilities/ }).click();
  const lightFinding = await selectSeededFinding(page, assetName);
  await lightFinding.click();
  await expect(page.getByRole("dialog")).toBeVisible();
  await scan(page, "finding and remediation dialog, light theme");
});

test("keyboard navigation and dialog focus return", async ({ page }) => {
  await login(page);
  const assetName = await seedFinding(page);
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible();

  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: "Skip to content" });
  await expect(skip).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main")).toBeFocused();

  const vulnerabilities = page.getByRole("button", {
    name: /^Vulnerabilities/,
  });
  await vulnerabilities.focus();
  await page.keyboard.press("Enter");
  await expect(
    page.getByRole("heading", { name: "Vulnerability inventory" }),
  ).toBeVisible();

  const finding = await selectSeededFinding(page, assetName);
  await finding.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(
    page.getByRole("button", { name: "Close dialog" }),
  ).toBeFocused();
  await page.keyboard.press("Escape");
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await expect(finding).toBeFocused();
});
