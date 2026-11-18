/* The Report view from the Core API (against the stand-in, e2e/core-api-stub.mjs): with no
   assessment picked, the API's assessments as a table, each row opening its report; one
   assessment's summary strip and its report versions; a signed-off version downloads its files
   through the dashboard, one whose review is pending says so and offers none, a refused download
   says what the API said; an unknown id keeps the picker; and the picker's choice is shared
   with the Findings view (`?assessment=`). */
import { type Page } from "@playwright/test";

import { apiId } from "./core-api-ids.mjs";
import { expect, test } from "./fixtures";
import { hydrated, newest, sample, signIn } from "./support";

/** The runs with one report version (the stand-in gives the newest twelve: core-api-stub.mjs LONG). */
const runs = () => sample().filter((a) => a.uid !== newest().uid);
const shown = (a: ReturnType<typeof sample>[number]) => a.findings.filter((f) => f.status !== "false-positive" && f.severity.toUpperCase() !== "INFO");
const versions = (page: Page) => page.getByRole("list", { name: "Report versions" }).getByRole("listitem");
const picker = (page: Page) => page.locator('[data-view-pane="reports"]').getByRole("combobox", { name: "Assessment" });

async function openReport(page: Page, uid: string | null) {
  await signIn(page);
  await page.goto(uid ? `/?view=reports&assessment=${apiId(uid)}` : "/?view=reports");
  await hydrated(page);
}

test("with no assessment picked, every Core API assessment is a row that opens its report", async ({ page }) => {
  await openReport(page, null);
  const all = sample();
  const table = page.getByRole("table", { name: "Core API assessments" });
  await expect(table.locator("tbody tr")).toHaveCount(all.length);
  const a = runs().find((x) => x.status === "Completed")!;
  await table.locator(`a[href*="assessment=${apiId(a.uid)}"]`).click(); // several runs may share a label
  await expect(page).toHaveURL(new RegExp(`view=reports&assessment=${apiId(a.uid)}`));
  await expect(versions(page)).toHaveCount(1);
});

test("a signed-off report shows its summary and downloads each file through the dashboard", async ({ page }) => {
  const a = runs().find((x) => x.status === "Completed" && shown(x).length > 0)!;
  await openReport(page, a.uid);
  const strip = page.getByRole("group", { name: "Report summary" });
  await expect(strip).toContainText("Findings");
  await expect(strip.locator('section[aria-label="Findings"] [data-countup]').first()).toHaveText(String(shown(a).length));
  const v1 = versions(page).first();
  await expect(v1).toContainText("v1");
  await expect(v1).toContainText("Ready");
  await expect(v1).toContainText("Signed off");
  const buttons = v1.getByRole("button", { name: /^Download version 1 as / });
  await expect(buttons).toHaveText(["PDF", "DOCX", "JSON"]);
  const saved = page.waitForEvent("download");
  await buttons.nth(0).click();
  expect((await saved).suggestedFilename()).toBe(`${a.assessment_id || a.uid}-v1.pdf`);
  await expect(page.locator(".dash-report-file")).toHaveText(`Saved ${a.assessment_id || a.uid}-v1.pdf.`);
});

test("a report whose review is pending says so and offers no file", async ({ page }) => {
  const a = runs().find((x) => x.status !== "Completed" && x.status !== "Stopped")!;
  await openReport(page, a.uid);
  const v1 = versions(page).first();
  await expect(v1).toContainText("Review pending");
  await expect(v1).toContainText("Waiting for a person to approve the review in the TUI.");
  await expect(v1.getByRole("button")).toHaveCount(0);
});

test("an assessment with no report yet says where reports come from", async ({ page }) => {
  const a = runs().find((x) => x.status === "Stopped")!;
  await openReport(page, a.uid);
  await expect(page.getByText("No report for this assessment yet. Make one in the TUI")).toBeVisible();
});

test("a download the API refuses says what it said, and saves nothing", async ({ page }) => {
  const a = runs().find((x) => x.status === "Completed")!;
  await openReport(page, a.uid);
  await page.route("**/api/core-reports/*/download?format=DOCX", (route) =>
    route.fulfill({ status: 409, contentType: "application/json", body: JSON.stringify({ code: "REPORT_FILE_CHANGED", message: "The DOCX file changed after the sign-off." }) }),
  );
  let downloads = 0;
  page.on("download", () => (downloads += 1));
  await versions(page).first().getByRole("button", { name: "Download version 1 as DOCX" }).click();
  await expect(page.getByRole("alert").filter({ hasText: "The DOCX file changed after the sign-off. (REPORT_FILE_CHANGED)" })).toBeVisible();
  expect(downloads).toBe(0);
});

test("an assessment id the Core API doesn't know shows the not-found note without a picker", async ({ page }) => {
  await signIn(page);
  await page.goto("/?view=reports&assessment=99999999-9999-4999-8999-999999999999");
  await expect(page.locator('[data-view-pane="reports"]').getByText("The Core API has no assessment with that id. Pick another one.")).toBeVisible();
  await expect(picker(page)).toHaveCount(0);
});

test("picking an assessment in Reports shares ?assessment= with the Findings view", async ({ page }) => {
  await openReport(page, null);
  const a = runs().find((x) => x.status === "Completed" && shown(x).length > 0)!;
  await page.getByRole("table", { name: "Core API assessments" }).locator(`a[href*="assessment=${apiId(a.uid)}"]`).click();
  await expect(page).toHaveURL(new RegExp(`assessment=${apiId(a.uid)}`));
  await expect(versions(page)).toHaveCount(1);
  await page.click('nav[aria-label="Views"] button[aria-label^="Findings"]');
  await expect(page).toHaveURL(new RegExp(`view=findings.*assessment=${apiId(a.uid)}|assessment=${apiId(a.uid)}.*view=findings`));
  await expect(page.locator('[data-view-pane="findings"] ul.dash-findings-rows > li')).toHaveCount(shown(a).length);
});
