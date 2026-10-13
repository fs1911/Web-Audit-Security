/**
 * End-to-End-Abnahmetest gegen das lokale, isolierte Testziel (testtarget).
 * Startet: Testziel, Web-App (next start), Scan-Runner, Dispatcher – als getrennte Prozesse.
 * Voraussetzungen: Postgres, `npm run build`, OWASP ZAP unter ZAP_HOME_DIR.
 *
 * Prüft die Abnahmekriterien 1–10 aus dem Auftrag und schreibt var/e2e-result.json.
 */
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import crypto from "node:crypto";
import { eq, sql } from "drizzle-orm";
import { drizzle } from "drizzle-orm/postgres-js";
import { migrate } from "drizzle-orm/postgres-js/migrator";
import postgres from "postgres";

const DB_URL = process.env.E2E_DATABASE_URL ?? "postgres://webaudit:webaudit@localhost:5432/webaudit_e2e";
const SECRET_TOKEN = "tt-session-SuperGeheim-4711";
const env: Record<string, string> = {
  PATH: process.env.PATH!,
  HOME: process.env.HOME ?? "/tmp",
  NODE_ENV: "development",
  DATABASE_URL: DB_URL,
  APP_ENCRYPTION_KEY: crypto.randomBytes(32).toString("base64"),
  RUNNER_CALLBACK_SECRET: crypto.randomBytes(32).toString("hex"),
  RUNNER_SHARED_SECRET: crypto.randomBytes(32).toString("hex"),
  APP_URL: "http://127.0.0.1:3100",
  APP_INTERNAL_URL: "http://127.0.0.1:3100",
  RUNNER_URL: "http://127.0.0.1:8788",
  RUNNER_PORT: "8788",
  ZAP_HOME_DIR: process.env.ZAP_HOME_DIR ?? "/opt/zap",
  STORAGE_DIR: "./var/e2e-storage",
  NETGUARD_TEST_ALLOW_CIDRS: "127.0.0.1/32",
  NETGUARD_TEST_ALLOW_PORTS: "8081,8443",
  WEBAUDIT_ALLOW_INVALID_CERTS: "true",
  WEBAUDIT_HTTP_PROBE_PORT: "8081",
  TESTTARGET_SESSION_TOKEN: SECRET_TOKEN,
  NEXT_TELEMETRY_DISABLED: "1",
};
Object.assign(process.env, env);

const procs: Record<string, ChildProcess> = {};
const logs: Record<string, string> = {};
function start(name: string, cmd: string, args: string[], extra: Record<string, string> = {}) {
  logs[name] ??= "";
  const p = spawn(cmd, args, { env: { ...env, ...extra } as unknown as NodeJS.ProcessEnv, stdio: ["ignore", "pipe", "pipe"], detached: true });
  p.stdout!.on("data", (d) => (logs[name] += d.toString()));
  p.stderr!.on("data", (d) => (logs[name] += d.toString()));
  procs[name] = p;
}
async function stop(name: string) {
  const p = procs[name];
  delete procs[name];
  if (!p?.pid) return;
  try {
    process.kill(-p.pid, "SIGTERM");
  } catch {
    return;
  }
  // Warten, bis die Prozessgruppe wirklich beendet ist (sonst blockiert sie Ports für den Neustart)
  for (let i = 0; i < 60; i++) {
    try {
      process.kill(-p.pid, 0);
    } catch {
      return;
    }
    await sleep(500);
  }
  try {
    process.kill(-p.pid, "SIGKILL");
  } catch {
    /* beendet */
  }
}
const sleep = (ms: number) => new Promise((r) => setTimeout(r, ms));
async function waitHttp(url: string, insecure = false) {
  for (let i = 0; i < 90; i++) {
    try {
      execFileSync("curl", ["-s", "-o", "/dev/null", "--noproxy", "*", ...(insecure ? ["-k"] : []), url]);
      return;
    } catch {
      await sleep(1000);
    }
  }
  throw new Error(`Nicht erreichbar: ${url}`);
}

const results: { criterion: string; ok: boolean; detail: string }[] = [];
function check(criterion: string, ok: boolean, detail: string) {
  results.push({ criterion, ok, detail });
  console.log(`${ok ? "✔" : "✘"} ${criterion} – ${detail}`);
}

async function main() {
  fs.rmSync("var/e2e-storage", { recursive: true, force: true });
  fs.rmSync("var/testtarget/forbidden.log", { force: true });
  fs.rmSync("var/testtarget/hits.log", { force: true });
  const admin = postgres(DB_URL.replace(/\/[^/]+$/, "/postgres"), { max: 1 });
  await admin.unsafe("DROP DATABASE IF EXISTS webaudit_e2e WITH (FORCE)").catch(() => undefined);
  await admin.unsafe("CREATE DATABASE webaudit_e2e");
  await admin.end();
  const mig = postgres(DB_URL, { max: 1 });
  await migrate(drizzle(mig), { migrationsFolder: "./drizzle" });
  await mig.end();

  // Dynamische Imports nach Setzen der Umgebung
  const { getDb, closeDb } = await import("../src/lib/db");
  const S = await import("../src/lib/db/schema");
  const { registerUser, createSession } = await import("../src/lib/auth/session");
  const { startScan, requestCancel } = await import("../src/lib/scans/service");
  const { createReport } = await import("../src/lib/reports/service");
  const { verifyFile } = await import("../src/lib/verification");
  const { validateUrl, loadPolicy } = await import("../src/lib/security/netguard");
  const { checkScope } = await import("../src/lib/security/scope");
  const { encryptSecret, randomToken } = await import("../src/lib/security/crypto");
  const { getStore } = await import("../src/lib/storage");
  const db = getDb();

  start("testtarget", "node", ["testtarget/server.mjs"]);
  start("web", "npx", ["next", "start", "-p", "3100", "-H", "127.0.0.1"]);
  start("runner", "npx", ["tsx", "src/runner/server.ts"]);
  start("dispatcher", "npx", ["tsx", "src/worker/main.ts"]);
  await waitHttp("https://127.0.0.1:8443/", true);
  await waitHttp("http://127.0.0.1:3100/login");
  await waitHttp("http://127.0.0.1:8788/health");

  const waitScan = async (id: string, timeoutMs = 10 * 60_000) => {
    const t0 = Date.now();
    for (;;) {
      const [s] = await db.select().from(S.scans).where(eq(S.scans.id, id));
      if (s && ["completed", "failed", "cancelled"].includes(s.status)) return s;
      if (Date.now() - t0 > timeoutMs) throw new Error(`Zeitüberschreitung Scan ${id} (${s?.status}/${s?.phase})`);
      await sleep(2000);
    }
  };

  // ---------- 1. Verifiziertes eigenes Testziel hinzufügen ----------
  const { user: ua, org: oa } = await registerUser(db, { email: "e2e-a@example.ch", name: "E2E A", password: "e2e-passwort-lang-genug", orgName: "E2E Org A" });
  const { user: ub } = await registerUser(db, { email: "e2e-b@example.ch", name: "E2E B", password: "e2e-passwort-lang-genug", orgName: "E2E Org B" });
  const [site] = await db
    .insert(S.sites)
    .values({ orgId: oa.id, name: "Lokales Testziel", baseUrl: "https://127.0.0.1:8443/", environment: "staging", ownerName: "E2E A", authorizationConfirmedAt: new Date(), authorizationConfirmedBy: ua.id, authorizationStatement: "Isoliertes lokales Testziel (testtarget)" })
    .returning();
  const token = randomToken(24);
  const [host] = await db.insert(S.siteHosts).values({ siteId: site!.id, host: "127.0.0.1", verificationToken: token }).returning();
  const wrong = await verifyFile("127.0.0.1", token, { scheme: "https", port: 8443, allowInvalidCerts: true });
  fs.writeFileSync("var/testtarget/verification-token.txt", token);
  const ok = await verifyFile("127.0.0.1", token, { scheme: "https", port: 8443, allowInvalidCerts: true });
  if (ok.ok) await db.update(S.siteHosts).set({ verifiedAt: new Date(), verificationMethod: "file" }).where(eq(S.siteHosts.id, host!.id));
  check("1 Verifiziertes Testziel hinzufügen", !wrong.ok && ok.ok, `ohne Token: ${wrong.detail}; mit Token: ${ok.detail}`);

  // ---------- 7. Interne/nicht freigegebene Ziele blockiert ----------
  const blocked: string[] = [];
  for (const u of ["http://169.254.169.254/latest/meta-data/", "http://10.0.0.1/", "http://localhost/", "http://[::1]/", "http://2130706433/", "https://user:pw@example.ch/"]) {
    try {
      validateUrl(u, loadPolicy({ NODE_ENV: "production" } as NodeJS.ProcessEnv));
    } catch {
      blocked.push(u);
    }
  }
  const scopeNow = { hosts: ["127.0.0.1"], includePaths: ["/"], excludePaths: [] };
  const foreign = !checkScope("https://example.org/", scopeNow).inScope && !checkScope("https://www.127.0.0.1.nip.io/", scopeNow).inScope;
  const [unverified] = await db.insert(S.sites).values({ orgId: oa.id, name: "Fremd", baseUrl: "https://example.org/", environment: "production", ownerName: "x", authorizationConfirmedAt: new Date(), authorizationStatement: "x" }).returning();
  await db.insert(S.siteHosts).values({ siteId: unverified!.id, host: "example.org", verificationToken: "x" });
  let unverifiedRejected = "";
  await startScan(db, ua.id, unverified!, { siteId: unverified!.id, mode: "baseline", confirmScope: true }).catch((e) => (unverifiedRejected = (e as Error).message));

  // ---------- 2./3. Echter Basisscan über den Worker ----------
  const s1 = await startScan(db, ua.id, site!, { siteId: site!.id, mode: "baseline", confirmScope: true, limits: { maxDurationMinutes: 8, requestsPerSecond: 10 } });
  const r1 = await waitScan(s1.id);
  const f1 = await db.select().from(S.findings).where(eq(S.findings.scanId, s1.id));
  check("2 Echter Basisscan über Worker", r1.status === "completed" && (r1.toolVersions["OWASP ZAP"] ?? "").startsWith("2."), `Status ${r1.status}, Werkzeuge ${JSON.stringify(r1.toolVersions)}, ${r1.executedMethods.length} Methoden${r1.error ? `, Fehler: ${r1.error}` : ""}`);
  const withEvidence = f1.filter((f) => f.evidence.length > 10);
  const zapFindings = f1.filter((f) => f.tool === "OWASP ZAP");
  const gitFinding = f1.find((f) => f.checkId === "WA-CFG-01");
  check("3 Echte Feststellungen mit Nachweisen", f1.length > 5 && withEvidence.length === f1.length && Boolean(gitFinding), `${f1.length} Feststellungen (davon ${zapFindings.length} aus ZAP), alle mit Nachweis; Beispiel: «${gitFinding?.title}» – ${gitFinding?.evidence.split("\n")[0]}`);

  // ---------- 4. Nicht geprüfte Bereiche bleiben nicht geprüft ----------
  const cov1 = await db.select().from(S.coverageResults).where(eq(S.coverageResults.scanId, s1.id));
  const rj = await createReport(db, s1.id, "json", ua.id);
  const rp = await createReport(db, s1.id, "pdf", ua.id);
  const json1 = JSON.parse(new TextDecoder().decode(await getStore().get(rj.objectKey)));
  const notCovered = json1.notCoveredByThisMode.map((c: { checkId: string }) => c.checkId);
  check("4 Nicht geprüfte Bereiche ausdrücklich ausgewiesen", notCovered.includes("WA-MAN-01") && notCovered.includes("WA-AUTH-02") && cov1.length > 0, `${cov1.filter((c) => c.state === "tested").length} geprüft, ${cov1.filter((c) => c.state !== "tested").length} nicht geprüft/n.a./Fehler; nicht Bestandteil des Modus: ${notCovered.join(", ")}`);

  // ---------- 5. PDF + JSON ----------
  const pdfBytes = await getStore().get(rp.objectKey);
  const session = await createSession(db, ua.id);
  const sessionB = await createSession(db, ub.id);
  const dl = await fetch(`http://127.0.0.1:3100/api/reports/${rp.id}`, { headers: { cookie: `wa_session=${session.token}` } });
  const dlB = await fetch(`http://127.0.0.1:3100/api/reports/${rp.id}`, { headers: { cookie: `wa_session=${sessionB.token}` } });
  const dlAnon = await fetch(`http://127.0.0.1:3100/api/reports/${rp.id}`);
  fs.mkdirSync("var/e2e-artifacts", { recursive: true });
  fs.writeFileSync("var/e2e-artifacts/bericht-basisscan.pdf", pdfBytes);
  fs.writeFileSync("var/e2e-artifacts/bericht-basisscan.json", JSON.stringify(json1, null, 2));
  check("5 PDF- und JSON-Bericht", Buffer.from(pdfBytes.slice(0, 5)).toString() === "%PDF-" && json1.findings.length === f1.length && dl.status === 200 && dlB.status === 404 && dlAnon.status === 401, `PDF ${pdfBytes.length} Byte, JSON ${json1.findings.length} Feststellungen; Download Eigentümer ${dl.status}, fremde Org ${dlB.status}, anonym ${dlAnon.status}`);

  // ---------- Authentifizierter Scan (für 9. Zugangsdaten) ----------
  const [cred] = await db.insert(S.credentials).values({ siteId: site!.id, label: "Admin-Test", kind: "header", headerName: "Authorization", encryptedValue: encryptSecret(`Bearer ${SECRET_TOKEN}`), verifyUrl: "https://127.0.0.1:8443/admin", logoutUrl: "https://127.0.0.1:8443/logout" }).returning();
  const sa = await startScan(db, ua.id, site!, { siteId: site!.id, mode: "authenticated", confirmScope: true, credentialIds: [cred!.id], limits: { maxDurationMinutes: 8, requestsPerSecond: 10 } });
  const ra = await waitScan(sa.id);
  const fa = await db.select().from(S.findings).where(eq(S.findings.scanId, sa.id));
  const logoutFinding = fa.find((f) => f.checkId === "WA-AUTH-02");
  const adminHits = fs.readFileSync("var/testtarget/hits.log", "utf8").split("\n").filter((l) => l.includes("/admin/")).length;
  const raj = await createReport(db, sa.id, "json", ua.id);
  const rap = await createReport(db, sa.id, "pdf", ua.id);

  // ---------- 9. Zugangsdaten nicht in Reports oder Logs ----------
  const dump = JSON.stringify(await db.execute(sql`SELECT (SELECT json_agg(f) FROM findings f) AS f, (SELECT json_agg(e) FROM scan_events e) AS e, (SELECT json_agg(a) FROM audit_log a) AS a, (SELECT json_agg(s) FROM scans s) AS s, (SELECT json_agg(c) FROM coverage_results c) AS c`));
  const reportTexts = [new TextDecoder().decode(await getStore().get(raj.objectKey)), Buffer.from(await getStore().get(rap.objectKey)).toString("latin1")];
  const leaks = [dump, ...reportTexts, logs.web ?? "", logs.runner ?? "", logs.dispatcher ?? ""].filter((t) => t.includes(SECRET_TOKEN)).length;
  check("B Authentifizierter Scan (Testrolle getrennt)", ra.status === "completed" && fa.some((f) => f.authContext === "Rolle: Admin-Test") && Boolean(logoutFinding) && adminHits > 0, `Status ${ra.status}; ${fa.length} Feststellungen; geschützte Seiten abgerufen: ${adminHits}; «${logoutFinding?.title}»`);
  check("9 Zugangsdaten nicht in Reports/Logs", leaks === 0, `Testtoken in DB-Ergebnistabellen, Berichten und Prozess-Logs gefunden: ${leaks}×`);

  // ---------- 8. Abbruch ----------
  const sc = await startScan(db, ua.id, site!, { siteId: site!.id, mode: "baseline", confirmScope: true });
  for (let i = 0; i < 120; i++) {
    const [s] = await db.select().from(S.scans).where(eq(S.scans.id, sc.id));
    if (s?.status === "running" && (s.phase ?? "").includes("Spider")) break;
    await sleep(1000);
  }
  const [running] = await db.select().from(S.scans).where(eq(S.scans.id, sc.id));
  const cancelRequestedAt = Date.now();
  await requestCancel(db, ua.id, running!);
  const rc = await waitScan(sc.id, 120_000);
  await sleep(4000);
  let zapLeft = "";
  try {
    zapLeft = execFileSync("pgrep", ["-f", "webaudit-zap-"]).toString().trim();
  } catch {
    zapLeft = "";
  }
  const fc = await db.select().from(S.findings).where(eq(S.findings.scanId, sc.id));
  check("8 Scan-Abbruch", rc.status === "cancelled" && fc.length === 0 && zapLeft === "", `Status ${rc.status} nach ${Math.round((Date.now() - cancelRequestedAt) / 1000)} s (Phase beim Abbruch: ${running!.phase}); verbleibende ZAP-Prozesse: ${zapLeft || "keine"}; übernommene Teilergebnisse: ${fc.length}`);

  // ---------- 6. Wiederholungsscan nach Behebung + Vergleich ----------
  await stop("testtarget");
  await sleep(1500);
  start("testtarget", "node", ["testtarget/server.mjs"], { TESTTARGET_FIXED: "1" });
  await waitHttp("https://127.0.0.1:8443/", true);
  const s3 = await startScan(db, ua.id, site!, { siteId: site!.id, mode: "baseline", confirmScope: true, limits: { maxDurationMinutes: 8, requestsPerSecond: 10 } });
  const r3 = await waitScan(s3.id);
  const r3j = await createReport(db, s3.id, "json", ua.id);
  const j3 = JSON.parse(new TextDecoder().decode(await getStore().get(r3j.objectKey)));
  fs.writeFileSync("var/e2e-artifacts/bericht-wiederholung.json", JSON.stringify(j3, null, 2));
  fs.writeFileSync("var/e2e-artifacts/bericht-wiederholung.pdf", await getStore().get((await createReport(db, s3.id, "pdf", ua.id)).objectKey));
  const prevRetested = (await db.select().from(S.findings).where(eq(S.findings.scanId, s1.id))).filter((f) => f.retestResult?.includes("nicht mehr gefunden")).length;
  check("6 Wiederholungsscan vergleichbar", r3.status === "completed" && r3.previousScanId === s1.id && j3.comparison?.resolved.length > 0, `Vorscan ${r3.previousScanId?.slice(0, 8)}; neu ${j3.comparison?.newCount}, behoben ${j3.comparison?.resolved.length}, unverändert ${j3.comparison?.unchanged}, nicht erneut geprüft ${j3.comparison?.notRetested}; Nachprüfungsvermerk an ${prevRetested} alten Feststellungen`);

  const forbidden = fs.existsSync("var/testtarget/forbidden.log") ? fs.readFileSync("var/testtarget/forbidden.log", "utf8").trim() : "";
  check("7 Interne/nicht freigegebene Ziele blockiert", blocked.length === 6 && foreign && /verifiziert/.test(unverifiedRejected) && forbidden === "", `${blocked.length}/6 interne URLs abgelehnt; fremde Hosts ausserhalb Scope: ${foreign}; unverifizierte Website: «${unverifiedRejected}»; verbotene Aufrufe am Testziel (Formular-POST, /danger/*): ${forbidden ? forbidden : "keine"}`);

  // ---------- 10. Fehlende Infrastruktur ----------
  await stop("runner");
  await sleep(1500);
  start("runner", "npx", ["tsx", "src/runner/server.ts"], { ZAP_HOME_DIR: "/nicht/vorhanden" });
  await waitHttp("http://127.0.0.1:8788/health");
  const s4 = await startScan(db, ua.id, site!, { siteId: site!.id, mode: "baseline", confirmScope: true });
  const r4 = await waitScan(s4.id, 120_000);
  const f4 = await db.select().from(S.findings).where(eq(S.findings.scanId, s4.id));
  await stop("runner");
  await sleep(1000);
  const s5 = await startScan(db, ua.id, site!, { siteId: site!.id, mode: "baseline", confirmScope: true });
  const r5 = await waitScan(s5.id, 120_000);
  check("10 Ehrliche Fehlermeldung bei fehlender Infrastruktur", r4.status === "failed" && f4.length === 0 && r5.status === "failed", `ohne ZAP: «${r4.error}»; ohne Runner: «${r5.error}»`);

  // Ungültige Callback-Signatur
  const [job] = await db.select().from(S.scanJobs).where(eq(S.scanJobs.scanId, s1.id));
  const forged = await fetch(`http://127.0.0.1:3100/api/internal/jobs/${job!.id}/events`, { method: "POST", headers: { "x-webaudit-ts": String(Date.now()), "x-webaudit-sig": "0".repeat(64) }, body: JSON.stringify({ type: "failed", error: "x" }) });
  check("Callback-Schutz", forged.status === 401, `gefälschter Runner-Callback → HTTP ${forged.status}`);

  await closeDb();
}

main()
  .catch((e) => {
    console.error("E2E abgebrochen:", e);
    results.push({ criterion: "Ablauf", ok: false, detail: String(e) });
  })
  .finally(async () => {
    for (const n of Object.keys(procs)) await stop(n);
    fs.mkdirSync("var", { recursive: true });
    fs.writeFileSync("var/e2e-result.json", JSON.stringify({ at: new Date().toISOString(), results }, null, 2));
    fs.writeFileSync("var/e2e-process-logs.txt", Object.entries(logs).map(([k, v]) => `===== ${k} =====\n${v}`).join("\n"));
    const failed = results.filter((r) => !r.ok).length;
    console.log(`\n${results.length - failed}/${results.length} Abnahmeprüfungen bestanden.`);
    process.exit(failed ? 1 : 0);
  });
