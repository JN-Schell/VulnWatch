import { test as base, expect } from "@playwright/test";

type BrowserFixtures = {
  rateLimitGuard: void;
};

export const test = base.extend<BrowserFixtures>({
  rateLimitGuard: [
    async ({ page }, use) => {
      const blockedUrls: string[] = [];
      page.on("response", (response) => {
        if (response.status() === 429) blockedUrls.push(response.url());
      });
      await use();
      expect(
        blockedUrls,
        `Browser test received a 429 response. Keep the suite within the production request budget instead of bypassing the limiter:\n${blockedUrls.join("\n")}`,
      ).toEqual([]);
    },
    { auto: true },
  ],
});

export { expect } from "@playwright/test";
