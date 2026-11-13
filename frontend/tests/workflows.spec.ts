import { test, expect } from "@playwright/test";
import path from "node:path";

const password = process.env.E2E_PASSWORD;
if (!password)
  throw new Error(
    "Set E2E_PASSWORD for the administrator bootstrapped in the test database",
  );

test.beforeEach(async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("Email address").fill("admin@example.com");
  await page.getByLabel("Password", { exact: true }).fill(password);
  await page.getByRole("button", { name: "Sign in to workspace" }).click();
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible();
});

test("real import, deduplication, assignment and verified remediation", async ({
  page,
}) => {
  await page.getByRole("button", { name: "Assets", exact: true }).click();
  await page.getByRole("button", { name: "Add asset", exact: true }).click();
  await page.getByLabel("Asset identifier").fill("server-01");
  await page.getByLabel("Owner", { exact: true }).fill("Security engineering");
  await page.getByRole("button", { name: "Save asset" }).click();
  await expect(page.getByRole("dialog")).not.toBeVisible();
  await page.getByRole("button", { name: "Imports", exact: true }).click();
  await page
    .getByLabel("Scan result file")
    .setInputFiles(path.resolve("../samples/generic.json"));
  await page
    .getByRole("button", { name: "Validate & import findings" })
    .click();
  await expect(page.getByRole("status")).toContainText("Import processed");
  await page
    .getByLabel("Scan result file")
    .setInputFiles(path.resolve("../samples/generic.json"));
  await page
    .getByRole("button", { name: "Validate & import findings" })
    .click();
  await expect(
    page.getByRole("row").filter({ hasText: "generic-json" }).first(),
  ).toContainText("2");
  await page.getByRole("button", { name: /^Vulnerabilities/ }).click();
  await page.getByLabel("Search findings").fill("Log4j");
  await page
    .getByRole("button", {
      name: "Apache Log4j remote code execution",
      exact: true,
    })
    .click();
  await expect(page.getByRole("dialog")).toContainText("Observations");
  const dialog = page.getByRole("dialog");
  await dialog
    .getByLabel("Status", { exact: true })
    .selectOption("in_progress");
  await dialog
    .getByLabel("Assigned to")
    .selectOption({ label: "Security Administrator" });
  await dialog
    .getByLabel("Notes / evidence")
    .fill("Remediation assigned to the security team");
  await dialog.getByRole("button", { name: "Record update" }).click();
  await expect(dialog.getByLabel("Status", { exact: true })).toHaveValue(
    "in_progress",
  );
  await dialog.getByLabel("Status", { exact: true }).selectOption("mitigated");
  await dialog.getByLabel("Activity type").selectOption("mitigation");
  await dialog
    .getByLabel("Notes / evidence")
    .fill("Updated package and restarted the service");
  await dialog.getByRole("button", { name: "Record update" }).click();
  await expect(dialog.getByLabel("Status", { exact: true })).toHaveValue(
    "mitigated",
  );
  await dialog.getByLabel("Status", { exact: true }).selectOption("verified");
  await dialog.getByLabel("Activity type").selectOption("verification");
  await dialog
    .getByLabel("Notes / evidence")
    .fill("Checked package inventory and attached change record SEC-42");
  await dialog.getByRole("button", { name: "Record update" }).click();
  await expect(dialog.getByLabel("Status", { exact: true })).toHaveValue(
    "verified",
  );
  await dialog.getByRole("button", { name: "Close dialog" }).click();
  await page.getByRole("button", { name: "Reports", exact: true }).click();
  const downloadPromise = page.waitForEvent("download");
  await page.getByRole("link", { name: "Export findings CSV" }).click();
  expect((await downloadPromise).suggestedFilename()).toBe(
    "vulnwatch-findings.csv",
  );
});

test("theme, mobile navigation, session and safe validation", async ({
  page,
}) => {
  await page.getByRole("button", { name: "Toggle theme" }).click();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.reload();
  await expect(
    page.getByRole("heading", { name: "Security overview" }),
  ).toBeVisible();
  await expect(page.locator("html")).toHaveAttribute("data-theme", "light");
  await page.setViewportSize({ width: 390, height: 844 });
  await page.getByRole("button", { name: "Open navigation" }).click();
  await page.getByRole("button", { name: "Imports", exact: true }).click();
  await page.getByLabel("Scan result file").setInputFiles({
    name: "malicious.json",
    mimeType: "application/json",
    buffer: Buffer.from("<script>alert(1)</script>"),
  });
  await page
    .getByRole("button", { name: "Validate & import findings" })
    .click();
  await expect(page.getByRole("alert")).toContainText("Malformed import");
  await page.getByRole("button", { name: "Open navigation" }).click();
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(
    page.getByRole("heading", { name: "Welcome back" }),
  ).toBeVisible();
});
