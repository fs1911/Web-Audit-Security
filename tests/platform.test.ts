import fs from "node:fs";
import { afterAll, beforeEach, describe, expect, it } from "vitest";
import { eq } from "drizzle-orm";
import { closeDb, type DB } from "../src/lib/db";
import { auditLog, coverageResults, findings, scanApprovals, scanJobs, scans, siteHosts, sites } from "../src/lib/db/schema";
import { registerUser, registrationAllowed, authenticate, createSession, validateSessionToken } from "../src/lib/auth/session";
import { AccessDeniedError, requireReport, requireScan, requireSite } from "../src/lib/auth/rbac";
import { buildJobSpec, claimNextJob, handleRunnerEvent, requestCancel, startScan, ScanRejectedError } from "../src/lib/scans/service";
import { createReport } from "../src/lib/reports/service";
import { getStore } from "../src/lib/storage";
import { encryptSecret } from "../src/lib/security/crypto";
import { credentials } from "../src/lib/db/schema";
import { resetDb } from "./helpers";
import type { RawFinding } from "../src/lib/findings/types";
import { runJob } from "../src/runner/pipeline";
import type { RunnerEvent } from "../src/lib/jobs/spec";

let db: DB;
const SECRET = "Bearer tt-session-SuperGeheim-4711";

async function setup() {
  db = await resetDb();
  const a = await registerUser(db, { email: "a@example.ch", name: "Anna", password: "korrekt-pferd-batterie", orgName: "Org A" });
  const b = await registerUser(db, { email: "b@example.ch", name: "Beat", password: "korrekt-pferd-batterie", orgName: "Org B" });
  const [site] = await db
    .insert(sites)
    .values({ orgId: a.org.id, name: "Testseite", baseUrl: "https://www.example.ch/", environment: "staging", ownerName: "Anna", authorizationConfirmedAt: new Date(), authorizationConfirmedBy: a.user.id, authorizationStatement: "Eigene Testseite" })
    .returning();
  await db.insert(siteHosts).values({ siteId: site!.id, host: "www.example.ch", verificationToken: "t", verifiedAt: new Date(), verificationMethod: "file" });
  return { a, b, site: site! };
}

const finding = (over: Partial<RawFinding> = {}): RawFinding => ({
  title: "Header X-Content-Type-Options fehlt",
  category: "HTTP-Header",
  kind: "configuration",
  severity: "low",
  confidence: "high",
  checkId: "WA-HDR-03",
  affectedUrl: "https://www.example.ch/",
  tool: "WebAudit Native Checks",
  toolVersion: "0.1.0",
  ruleId: "WA-HDR-03",
  authContext: "anonym",
  evidence: `GET https://www.example.ch/ → 200\nAuthorization: ${SECRET}`,
  description: "d",
  remediation: "r",
  references: [{ framework: "ASVS", version: "5.0.0", id: "3.4.4", verified: true }],
  externalLinks: [],
  ...over,
});

async function runToCompletion(scanId: string, list: RawFinding[]) {
  const claimed = await claimNextJob(db);
  expect(claimed?.scanId).toBe(scanId);
  await db.update(scans).set({ status: "running", startedAt: new Date() }).where(eq(scans.id, scanId));
  await handleRunnerEvent(db, claimed!.jobId, { type: "progress", phase: "Spider", progress: 40, message: `Test ${SECRET}` });
  await handleRunnerEvent(db, claimed!.jobId, { type: "results", findings: list, coverage: [{ checkId: "WA-HDR-03", state: "tested", method: "Header" }] });
  await handleRunnerEvent(db, claimed!.jobId, { type: "complete", toolVersions: { "WebAudit Native Checks": "0.1.0" }, executedMethods: ["Native"], unavailableAdapters: [] });
  return claimed!.jobId;
}

afterAll(async () => {
  await closeDb();
});

describe("Authentifizierung", () => {
  beforeEach(async () => void (await setup()));
  it("meldet an, sperrt nach wiederholten Fehlversuchen und validiert Sitzungen", async () => {
    const u = await authenticate(db, "a@example.ch", "korrekt-pferd-batterie", null);
    const s = await createSession(db, u.id);
    expect((await validateSessionToken(db, s.token))?.email).toBe("a@example.ch");
    expect(await validateSessionToken(db, s.token + "x")).toBeNull();
    for (let i = 0; i < 5; i++) await expect(authenticate(db, "a@example.ch", "falsch-falsch-falsch", null)).rejects.toThrow(/falsch/);
    await expect(authenticate(db, "a@example.ch", "korrekt-pferd-batterie", null)).rejects.toThrow(/Zu viele/);
  });
  it("Registrierung bei ALLOW_REGISTRATION=false nur für das erste Konto (Bootstrap)", async () => {
    const closed = { ALLOW_REGISTRATION: "false" } as unknown as NodeJS.ProcessEnv;
    expect(await registrationAllowed(db, closed)).toBe(false); // setup() hat bereits Konten angelegt
    await resetDb();
    expect(await registrationAllowed(db, closed)).toBe(true);
    expect(await registrationAllowed(db, {} as NodeJS.ProcessEnv)).toBe(true);
  });
  it("lehnt schwache Passwörter ab", async () => {
    await expect(registerUser(db, { email: "c@example.ch", name: "C", password: "kurz", orgName: "C" })).rejects.toThrow(/12 Zeichen/);
  });
});

describe("Mandantentrennung und Report-Zugriff", () => {
  it("verhindert Zugriff auf Websites, Scans und Berichte fremder Organisationen", async () => {
    const { a, b, site } = await setup();
    await expect(requireSite(db, b.user.id, site.id, "site.read")).rejects.toBeInstanceOf(AccessDeniedError);
    const scan = await startScan(db, a.user.id, site, { siteId: site.id, mode: "baseline", confirmScope: true });
    await expect(requireScan(db, b.user.id, scan.id, "scan.read")).rejects.toBeInstanceOf(AccessDeniedError);
    await runToCompletion(scan.id, [finding()]);
    const rep = await createReport(db, scan.id, "json", a.user.id);
    expect((await requireReport(db, a.user.id, rep.id)).id).toBe(rep.id);
    await expect(requireReport(db, b.user.id, rep.id)).rejects.toBeInstanceOf(AccessDeniedError);
    await expect(requireReport(db, b.user.id, "kein-uuid")).rejects.toBeInstanceOf(AccessDeniedError);
  });
});

describe("Scan-Freigaben", () => {
  it("verlangt Bestätigung, Berechtigung und verifizierte Hosts", async () => {
    const { a, site } = await setup();
    await expect(startScan(db, a.user.id, site, { siteId: site.id, mode: "baseline", confirmScope: false })).rejects.toThrow(ScanRejectedError);
    await db.update(siteHosts).set({ verifiedAt: null }).where(eq(siteHosts.siteId, site.id));
    await expect(startScan(db, a.user.id, site, { siteId: site.id, mode: "baseline", confirmScope: true })).rejects.toThrow(/verifiziert/);
    const [noAuth] = await db.update(sites).set({ authorizationConfirmedAt: null }).where(eq(sites.id, site.id)).returning();
    await expect(startScan(db, a.user.id, noAuth!, { siteId: site.id, mode: "baseline", confirmScope: true })).rejects.toThrow(/Prüfberechtigung/);
    const rejected = await db.select().from(auditLog).where(eq(auditLog.action, "scan.rejected"));
    expect(rejected.length).toBe(3);
  });
  it("aktive Prüfungen: nur mit Feature-Flag, gültiger Freigabe, im Zeitfenster und nicht auf Produktion", async () => {
    const { a, site } = await setup();
    delete process.env.ENABLE_ACTIVE_SCANS;
    await expect(startScan(db, a.user.id, site, { siteId: site.id, mode: "active", confirmScope: true })).rejects.toThrow(/deaktiviert/);
    process.env.ENABLE_ACTIVE_SCANS = "true";
    await expect(startScan(db, a.user.id, site, { siteId: site.id, mode: "active", confirmScope: true })).rejects.toThrow(/Freigabe/);
    const base = { siteId: site.id, mode: "active" as const, profile: "webaudit-safe", targetUrl: site.baseUrl, scopeSummary: "x", maxRequests: 100, requestsPerSecond: 2, approvedBy: a.user.id, statement: "Staging-Test" };
    const [expired] = await db.insert(scanApprovals).values({ ...base, windowStart: new Date(Date.now() - 7200e3), windowEnd: new Date(Date.now() - 3600e3) }).returning();
    await expect(startScan(db, a.user.id, site, { siteId: site.id, mode: "active", confirmScope: true, approvalId: expired!.id })).rejects.toThrow(/Zeitfenster/);
    const [valid] = await db.insert(scanApprovals).values({ ...base, windowStart: new Date(Date.now() - 60e3), windowEnd: new Date(Date.now() + 3600e3) }).returning();
    const [prodSite] = await db.update(sites).set({ environment: "production" }).where(eq(sites.id, site.id)).returning();
    await expect(startScan(db, a.user.id, prodSite!, { siteId: site.id, mode: "active", confirmScope: true, approvalId: valid!.id })).rejects.toThrow(/Produktion/);
    const [stagingSite] = await db.update(sites).set({ environment: "staging" }).where(eq(sites.id, site.id)).returning();
    const scan = await startScan(db, a.user.id, stagingSite!, { siteId: site.id, mode: "active", confirmScope: true, approvalId: valid!.id, limits: { maxRequests: 99999 } });
    expect(scan.limits.maxRequests).toBe(100); // Freigabe-Limit ist Obergrenze
    delete process.env.ENABLE_ACTIVE_SCANS;
  });
  it("verhindert parallele Scans derselben Website", async () => {
    const { a, site } = await setup();
    await startScan(db, a.user.id, site, { siteId: site.id, mode: "baseline", confirmScope: true });
    await expect(startScan(db, a.user.id, site, { siteId: site.id, mode: "baseline", confirmScope: true })).rejects.toThrow(/läuft bereits/);
  });
});

describe("Scanablauf, Abbruch und Geheimnisbereinigung", () => {
  it("anonymer Ablauf: speichert bereinigte, deduplizierte Feststellungen und markiert nicht gemeldete Prüfpunkte als nicht geprüft", async () => {
    const { a, site } = await setup();
    const scan = await startScan(db, a.user.id, site, { siteId: site.id, mode: "baseline", confirmScope: true });
    await runToCompletion(scan.id, [finding(), finding({ affectedUrl: "https://www.example.ch/b" })]);
    const fs1 = await db.select().from(findings).where(eq(findings.scanId, scan.id));
    expect(fs1).toHaveLength(1);
    expect(fs1[0]!.occurrences).toBe(2);
    expect(fs1[0]!.evidence).not.toContain("SuperGeheim");
    const cov = await db.select().from(coverageResults).where(eq(coverageResults.scanId, scan.id));
    expect(cov.find((c) => c.checkId === "WA-HDR-03")!.state).toBe("tested");
    expect(cov.find((c) => c.checkId === "WA-TLS-01")!.state).toBe("not_tested");
    const [done] = await db.select().from(scans).where(eq(scans.id, scan.id));
    expect(done!.status).toBe("completed");
  });
  it("authentifizierter Ablauf: entschlüsselt Testzugänge nur für die Job-Spezifikation", async () => {
    const { a, site } = await setup();
    const [cred] = await db.insert(credentials).values({ siteId: site.id, label: "Redaktor", kind: "header", headerName: "Authorization", encryptedValue: encryptSecret(SECRET), verifyUrl: "https://www.example.ch/admin" }).returning();
    expect(cred!.encryptedValue).not.toContain("SuperGeheim");
    await expect(startScan(db, a.user.id, site, { siteId: site.id, mode: "authenticated", confirmScope: true })).rejects.toThrow(/Testzugang/);
    const scan = await startScan(db, a.user.id, site, { siteId: site.id, mode: "authenticated", confirmScope: true, credentialIds: [cred!.id] });
    const [job] = await db.select().from(scanJobs).where(eq(scanJobs.scanId, scan.id));
    const spec = await buildJobSpec(db, job!.id, scan);
    expect(spec.auth!.roles[0]!.value).toBe(SECRET);
    expect(spec.callbackToken).not.toBe(process.env.RUNNER_CALLBACK_SECRET);
    await runToCompletion(scan.id, [finding({ authContext: "Rolle: Redaktor", evidence: `Antwort enthielt ${SECRET}` })]);
    const [f] = await db.select().from(findings).where(eq(findings.scanId, scan.id));
    expect(f!.authContext).toBe("Rolle: Redaktor");
    // Kein Klartext-Secret in DB-Tabellen mit Ergebnissen, Ereignissen oder Audit-Log
    const dump = JSON.stringify([await db.select().from(findings), await db.select().from(auditLog), await db.select().from(scans)]);
    expect(dump).not.toContain("SuperGeheim");
  });
  it("Abbruch: queued sofort, running über Callback-Antwort; Teilergebnisse werden verworfen", async () => {
    const { a, site } = await setup();
    const s1 = await startScan(db, a.user.id, site, { siteId: site.id, mode: "baseline", confirmScope: true });
    await requestCancel(db, a.user.id, s1);
    expect((await db.select().from(scans).where(eq(scans.id, s1.id)))[0]!.status).toBe("cancelled");

    const s2 = await startScan(db, a.user.id, site, { siteId: site.id, mode: "baseline", confirmScope: true });
    const claimed = await claimNextJob(db);
    const [running] = await db.update(scans).set({ status: "running" }).where(eq(scans.id, s2.id)).returning();
    await requestCancel(db, a.user.id, running!);
    const r = await handleRunnerEvent(db, claimed!.jobId, { type: "heartbeat" });
    expect(r.cancel).toBe(true);
    await handleRunnerEvent(db, claimed!.jobId, { type: "results", findings: [finding()], coverage: [] });
    await handleRunnerEvent(db, claimed!.jobId, { type: "complete", toolVersions: {}, executedMethods: [], unavailableAdapters: [], cancelled: true });
    expect((await db.select().from(scans).where(eq(scans.id, s2.id)))[0]!.status).toBe("cancelled");
    expect(await db.select().from(findings).where(eq(findings.scanId, s2.id))).toHaveLength(0);
  });
  it("Fehlschlag: Scan wird als fehlgeschlagen markiert, ohne Ergebnisse", async () => {
    const { a, site } = await setup();
    const s = await startScan(db, a.user.id, site, { siteId: site.id, mode: "baseline", confirmScope: true });
    const claimed = await claimNextJob(db);
    await handleRunnerEvent(db, claimed!.jobId, { type: "failed", error: `ZAP fehlt ${SECRET}` });
    const [row] = await db.select().from(scans).where(eq(scans.id, s.id));
    expect(row!.status).toBe("failed");
    expect(row!.error).not.toContain("SuperGeheim");
  });
});

describe("Runner ohne Infrastruktur", () => {
  it("liefert eine ehrliche Fehlermeldung statt simulierter Ergebnisse, wenn ZAP fehlt", async () => {
    const prev = process.env.ZAP_HOME_DIR;
    process.env.ZAP_HOME_DIR = "/nicht/vorhanden";
    const events: RunnerEvent[] = [];
    await runJob(
      { jobId: crypto.randomUUID(), scanId: crypto.randomUUID(), mode: "baseline", siteName: "x", environment: "staging", baseUrl: "https://www.example.ch/", scope: { hosts: ["www.example.ch"], includePaths: ["/"], excludePaths: [] }, limits: { maxDurationMinutes: 1, maxRequests: 10, requestsPerSecond: 1, maxDepth: 1, maxChildren: 1, threads: 1 }, callbackUrl: "http://x", callbackToken: "x".repeat(32) },
      async (e) => void events.push(e),
      new AbortController().signal,
    );
    process.env.ZAP_HOME_DIR = prev;
    expect(events.some((e) => e.type === "results")).toBe(false);
    const failed = events.find((e) => e.type === "failed");
    expect(failed && failed.type === "failed" && failed.error).toMatch(/ZAP nicht gefunden.*keine Ergebnisse/);
  });
});

describe("Berichte", () => {
  it("erzeugt PDF und JSON mit Hinweis, Abdeckung, Vergleich und ohne Secrets", async () => {
    const { a, site } = await setup();
    const s1 = await startScan(db, a.user.id, site, { siteId: site.id, mode: "baseline", confirmScope: true });
    await runToCompletion(s1.id, [finding(), finding({ title: "Server-Version", ruleId: "WA-HDR-06", checkId: "WA-HDR-03", category: "Informationspreisgabe" })]);
    const s2 = await startScan(db, a.user.id, site, { siteId: site.id, mode: "baseline", confirmScope: true });
    await runToCompletion(s2.id, [finding({ title: "Server-Version", ruleId: "WA-HDR-06", checkId: "WA-HDR-03", category: "Informationspreisgabe" })]);
    const json = await createReport(db, s2.id, "json", a.user.id);
    const pdf = await createReport(db, s2.id, "pdf", a.user.id);
    const jtext = new TextDecoder().decode(await getStore().get(json.objectKey));
    const j = JSON.parse(jtext);
    expect(j.disclaimer).toMatch(/Kein vollständiger Penetrationstest/);
    expect(j.comparison.resolved).toHaveLength(1);
    expect(j.metrics.coverage.implementedInMode).toBeGreaterThan(0);
    expect(j.notCoveredByThisMode.length).toBeGreaterThan(0);
    expect(j.findings[0].repairPrompt).toContain("Akzeptanzkriterien");
    expect(jtext).not.toContain("SuperGeheim");
    expect(jtext).not.toMatch(/website ist sicher/i);
    const pbytes = await getStore().get(pdf.objectKey);
    expect(Buffer.from(pbytes.slice(0, 5)).toString()).toBe("%PDF-");
    expect(pbytes.length).toBeGreaterThan(2000);
    // Nachprüfung: alte Feststellung erhält Ergebnis
    const old = await db.select().from(findings).where(eq(findings.scanId, s1.id));
    expect(old.find((f) => f.ruleId === "WA-HDR-03")!.retestResult).toMatch(/nicht mehr gefunden/);
    fs.rmSync("./var/test-storage", { recursive: true, force: true });
  });
});
