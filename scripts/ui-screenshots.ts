// Sichtprüfung der Oberfläche mit echten Daten aus der E2E-Datenbank (nur lokal).
import { chromium } from "playwright";
import fs from "node:fs";
const base = process.env.UI_BASE ?? "http://127.0.0.1:3200";
const out = process.env.UI_OUT ?? "var/screenshots";
fs.mkdirSync(out, { recursive: true });
const browser = await chromium.launch({ executablePath: process.env.CHROMIUM_PATH ?? "/opt/pw-browsers/chromium" });
const page = await browser.newPage({ viewport: { width: 1360, height: 900 } });
await page.goto(`${base}/login`);
await page.fill("#email", "e2e-a@example.ch");
await page.fill("#password", "e2e-passwort-lang-genug");
await page.click("button[type=submit]");
await page.waitForURL(`${base}/`);
const shots: [string, string][] = [["dashboard", "/"]];
const scanLinks = await page.$$eval("a[href^='/scans/']", (as) => as.map((a) => (a as HTMLAnchorElement).getAttribute("href")!));
const siteLinks = await page.$$eval("a[href^='/sites/']", (as) => as.map((a) => (a as HTMLAnchorElement).getAttribute("href")!).filter((h) => !h.endsWith("/new")));
if (siteLinks[0]) shots.push(["website", siteLinks[0]], ["scan-starten", `${siteLinks[0]}/scan`]);
const compare = scanLinks.find((h) => h.endsWith("/compare"));
if (compare) shots.push(["vergleich", compare], ["ergebnisse", compare.replace("/compare", "")]);
shots.push(["katalog", "/catalog"], ["audit-log", "/audit"], ["einstellungen", "/settings"]);
for (const [name, path] of shots) {
  await page.goto(`${base}${path}`);
  await page.screenshot({ path: `${out}/${name}.png`, fullPage: name !== "katalog" && name !== "ergebnisse" });
  console.log(`${name}: ${path}`);
}
if (compare) {
  await page.goto(`${base}${compare.replace("/compare", "")}`);
  const f = await page.$("a[href^='/findings/']");
  if (f) {
    await f.click();
    await page.waitForLoadState();
    await page.screenshot({ path: `${out}/feststellung.png`, fullPage: true });
    console.log("feststellung");
  }
}
await browser.close();
