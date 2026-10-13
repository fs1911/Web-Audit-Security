import type { JobSpec, RunnerEvent } from "../lib/jobs/spec";
import { loadPolicy, resolveSafe } from "../lib/security/netguard";
import { checkScope } from "../lib/security/scope";
import { EgressProxy } from "../lib/security/egress-proxy";
import { guardedRequest } from "../lib/security/http";
import { redact } from "../lib/security/redact";
import { refsForCheck } from "../lib/catalog";
import type { CoverageEntry, RawFinding } from "../lib/findings/types";
import { runNativeChecks, NATIVE_TOOL, NATIVE_VERSION } from "./native/checks";
import { runZapScan } from "./zap/scan";
import { zapAvailability } from "./zap/process";
import { cloneRepo, repoAdapterAvailability, runGitleaks, runOsv, runSemgrep, toolVersion } from "./repo/repo";

export type Emit = (e: RunnerEvent) => Promise<void>;

class Cancelled extends Error {}

/**
 * Führt einen Scan gemäss Job-Spezifikation aus. Erzeugt ausschliesslich Feststellungen aus
 * tatsächlich ausgeführten Werkzeugen. Fehlt ein benötigtes Werkzeug, schlägt der Scan mit
 * einer klaren Meldung fehl, statt Ergebnisse zu simulieren.
 */
export async function runJob(spec: JobSpec, emit: Emit, signal: AbortSignal): Promise<void> {
  const knownSecrets = [...(spec.auth?.roles.map((r) => r.value) ?? []), ...(spec.repo?.token ? [spec.repo.token] : [])];
  const log = (message: string, level: "info" | "warn" | "error" = "info") => void emit({ type: "progress", phase: "", progress: -1, message: redact(message, { knownSecrets }), level });
  const progress = (phase: string, pct: number, message?: string) => void emit({ type: "progress", phase, progress: Math.max(0, Math.min(100, Math.round(pct))), message });
  const check = () => {
    if (signal.aborted) throw new Cancelled("Abgebrochen");
  };

  try {
    if (spec.mode === "repository") return await runRepository(spec, emit, signal, knownSecrets, log, progress);

    // ---------- Vorabprüfung ----------
    progress("Vorabprüfung", 1);
    const policy = loadPolicy();
    const zap = zapAvailability();
    if (!zap.available) {
      await emit({ type: "failed", error: `Scan nicht gestartet: ${zap.reason}. Es wurden keine Ergebnisse erzeugt.`, unavailableAdapters: [{ adapter: "OWASP ZAP", reason: zap.reason }] });
      return;
    }
    const d = checkScope(spec.baseUrl, spec.scope, policy, { stateChangingGuard: false });
    if (!d.inScope) {
      await emit({ type: "failed", error: `Basis-URL ausserhalb des Scopes: ${d.reason}` });
      return;
    }
    for (const h of spec.scope.hosts) await resolveSafe(h, policy);
    if (spec.mode === "active") {
      if (!spec.active || new Date(spec.active.windowEnd).getTime() < Date.now()) {
        await emit({ type: "failed", error: "Aktive Prüfung ohne gültige Freigabe im Zeitfenster abgelehnt." });
        return;
      }
    }
    if (spec.mode === "authenticated" && !spec.auth?.roles.length) {
      await emit({ type: "failed", error: "Authentifizierter Scan ohne hinterlegte Testzugänge abgelehnt." });
      return;
    }

    const findings: RawFinding[] = [];
    const coverage: CoverageEntry[] = [];
    const executed: string[] = [];
    const versions: Record<string, string> = { [NATIVE_TOOL]: NATIVE_VERSION };
    const deadline = Date.now() + spec.limits.maxDurationMinutes * 60_000;

    // ---------- Egress-Proxy für ZAP ----------
    const proxy = new EgressProxy({
      scope: spec.scope,
      allowedMethods: ["GET", "HEAD"],
      maxRequests: spec.limits.maxRequests,
      requestsPerSecond: spec.limits.requestsPerSecond,
      policy,
    });
    const proxyPort = await proxy.listen();
    signal.addEventListener("abort", () => void proxy.close(), { once: true });

    try {
      // ---------- Native Checks (anonym) ----------
      check();
      progress("Native Prüfungen (TLS, Header, Cookies)", 3);
      const native = await runNativeChecks({ baseUrl: spec.baseUrl, scope: spec.scope, policy, authContext: "anonym", knownSecrets, allowInvalidCerts: spec.allowInvalidCerts, signal, log });
      findings.push(...native.findings);
      coverage.push(...native.coverage);
      executed.push("Native Prüfungen: TLS, HTTP→HTTPS, Sicherheits-Header, Cookies, Mixed Content, /.git/HEAD, security.txt");
      log(`Native Prüfungen abgeschlossen (${native.pagesFetched} Anfragen, ${native.findings.length} Beobachtungen).`);

      // ---------- ZAP ----------
      const runs: { authContext: string; headers?: { name: string; value: string }[]; seeds?: string[] }[] =
        spec.mode === "authenticated" ? spec.auth!.roles.map((r) => ({ authContext: `Rolle: ${r.label}`, headers: [roleHeader(r)], seeds: r.verifyUrl ? [r.verifyUrl] : [] })) : [{ authContext: "anonym" }];
      let totalUrls = 0;
      const allowedPorts = [...policy.allowedPorts];
      for (const [i, run] of runs.entries()) {
        check();
        if (Date.now() > deadline) {
          log(`Zeitlimit erreicht – ${run.authContext} nicht mehr geprüft.`, "warn");
          coverage.push({ checkId: "WA-AUTH-03", state: "not_tested", limitation: `Zeitlimit erreicht vor ${run.authContext}` });
          continue;
        }
        const base = 10 + (i / runs.length) * 80;
        const span = 80 / runs.length;
        const zr = await runZapScan({
          baseUrl: spec.baseUrl,
          scope: spec.scope,
          limits: { ...spec.limits, maxDurationMinutes: Math.max(1, Math.floor((deadline - Date.now()) / 60000 / (runs.length - i))) },
          allowedPorts,
          egressProxyPort: proxyPort,
          authContext: run.authContext,
          authHeaders: run.headers,
          seedUrls: (run.seeds ?? []).filter((u) => checkScope(u, spec.scope, policy).inScope),
          active: spec.mode === "active" ? { allowWriteEffects: spec.active?.allowWriteEffects === true } : undefined,
          knownSecrets,
          signal,
          onProgress: (phase, pct, msg) => progress(`${runs.length > 1 ? `[${run.authContext}] ` : ""}${phase}`, base + (pct / 100) * span, msg),
          log,
        });
        versions["OWASP ZAP"] = zr.version;
        totalUrls += zr.urlsFound;
        // Nur Feststellungen innerhalb des Scopes übernehmen (z. B. keine Antworten des Egress-Proxys)
        const inScope = zr.findings.filter((f) => !f.affectedUrl || checkScope(f.affectedUrl, spec.scope, policy, { stateChangingGuard: false }).inScope);
        mergeZapIntoNative(findings, inScope);
        if (spec.mode === "active") {
          executed.push(`ZAP aktive Prüfung, Profil webaudit-safe (Regeln: ${zr.activeRulesUsed.join(", ")})`);
          coverage.push({ checkId: "WA-ACT-01", state: "tested", method: `ZAP ascan, ${zr.activeRulesUsed.length} Regeln`, evidence: zr.activeRulesUsed.join(", ") });
        }
      }
      const stats = proxy.getStats();
      executed.push(`ZAP Spider (ohne Formularversand) + passive Regeln${spec.mode === "authenticated" ? ` für ${runs.length} Testrolle(n)` : ""}`);
      coverage.push({ checkId: "WA-CRAWL-01", state: "tested", method: "ZAP Spider", evidence: `${totalUrls} URLs im Scope erfasst; ${stats.allowed} Verbindungen erlaubt, ${stats.blocked} blockiert`, limitation: "Ohne JavaScript-Ausführung; begrenzt durch Request- und Zeitlimit" });
      coverage.push({ checkId: "WA-ZAP-PASSIVE", state: "tested", method: "ZAP passive Regeln", evidence: `${totalUrls} URLs passiv analysiert` });

      // ---------- Authentifizierungsprüfungen (nach ZAP, da Logout die Sitzung beendet) ----------
      if (spec.mode === "authenticated") {
        for (const role of spec.auth!.roles) {
          check();
          const r = await authChecks(spec, role, policy, knownSecrets);
          findings.push(...r.findings);
          coverage.push(...r.coverage);
        }
        coverage.push({ checkId: "WA-AUTH-03", state: "tested", method: "ZAP Spider je Testrolle", limitation: "Erreichbarkeit ≠ korrekte Berechtigung; Rollenprüfung manuell erforderlich" });
        executed.push("Sitzungs- und Logout-Prüfung je Testrolle");
      }
      progress("Ergebnisse übermitteln", 95);
      await emit({ type: "results", findings, coverage });
      await emit({ type: "complete", toolVersions: versions, executedMethods: executed, unavailableAdapters: [], egressStats: stats });
    } finally {
      await proxy.close().catch(() => undefined);
    }
  } catch (e) {
    if (e instanceof Cancelled || signal.aborted) {
      await emit({ type: "complete", toolVersions: {}, executedMethods: [], unavailableAdapters: [], cancelled: true });
      return;
    }
    await emit({ type: "failed", error: redact((e as Error).message, { knownSecrets }) });
  }
}

function roleHeader(r: NonNullable<JobSpec["auth"]>["roles"][number]): { name: string; value: string } {
  return r.kind === "cookie" ? { name: "Cookie", value: r.value } : { name: r.headerName || "Authorization", value: r.value };
}

/** Überschneidende ZAP-Regeln werden in die native Feststellung als weitere Fundstellen eingefügt. */
function mergeZapIntoNative(target: RawFinding[], zapFindings: (RawFinding & { nativeCheck?: string })[]) {
  for (const z of zapFindings) {
    if (z.nativeCheck) {
      const native = target.find((f) => f.checkId === z.nativeCheck && f.tool === NATIVE_TOOL && f.authContext === "anonym");
      if (native) {
        const extra = (native.otherUrls ??= []);
        if (z.affectedUrl && z.affectedUrl !== native.affectedUrl && !extra.includes(z.affectedUrl) && extra.length < 25) extra.push(z.affectedUrl);
        continue;
      }
    }
    const { nativeCheck: _n, ...rest } = z;
    target.push(rest);
  }
}

async function authChecks(spec: JobSpec, role: NonNullable<JobSpec["auth"]>["roles"][number], policy: ReturnType<typeof loadPolicy>, knownSecrets: string[]) {
  const findings: RawFinding[] = [];
  const coverage: CoverageEntry[] = [];
  const ctxLabel = `Rolle: ${role.label}`;
  const h = roleHeader(role);
  const ref = (id: string) => refsForCheck(id);
  if (!role.verifyUrl) {
    coverage.push({ checkId: "WA-AUTH-01", state: "not_tested", limitation: `Keine Prüf-URL für ${ctxLabel}` });
    coverage.push({ checkId: "WA-AUTH-02", state: "not_tested", limitation: `Keine Prüf-URL für ${ctxLabel}` });
    return { findings, coverage };
  }
  const opts = { scope: spec.scope, policy, allowInvalidCerts: spec.allowInvalidCerts, maxRedirects: 0 } as const;
  const withAuth = await guardedRequest(role.verifyUrl, { ...opts, headers: { [h.name]: h.value } });
  const anon = await guardedRequest(role.verifyUrl, opts);
  const distinguishable = withAuth.status !== anon.status || Math.abs(withAuth.body.length - anon.body.length) > 50;
  const ev = `GET ${role.verifyUrl} mit Testzugang → Status ${withAuth.status}, ${withAuth.body.length} Byte\nGET ${role.verifyUrl} ohne Zugang → Status ${anon.status}, ${anon.body.length} Byte`;
  if (!distinguishable) {
    findings.push({
      title: `Testzugang «${role.label}» nicht wirksam oder geschützte Seite öffentlich`, category: "Authentifizierung", kind: "suspicion", severity: "medium", confidence: "low", checkId: "WA-AUTH-01",
      affectedUrl: role.verifyUrl, method: "GET", tool: NATIVE_TOOL, toolVersion: NATIVE_VERSION, ruleId: "WA-AUTH-01", authContext: ctxLabel, evidence: redact(ev, { knownSecrets }),
      description: "Mit und ohne Testzugang liefert die Prüf-URL praktisch dieselbe Antwort. Entweder ist der Testzugang ungültig, oder die Seite ist ohne Anmeldung erreichbar.",
      remediation: "Testzugang erneuern. Falls die Seite geschützt sein soll: Zugriffskontrolle serverseitig erzwingen.",
      limitations: "Vergleich über Statuscode und Antwortlänge; keine inhaltliche Bewertung.", references: ref("WA-AUTH-01"), externalLinks: [],
    });
  }
  coverage.push({ checkId: "WA-AUTH-01", state: "tested", method: `Vergleich mit/ohne Zugang (${ctxLabel})`, evidence: redact(ev, { knownSecrets }) });

  if (!role.logoutUrl) {
    coverage.push({ checkId: "WA-AUTH-02", state: "not_tested", limitation: `Keine Logout-URL für ${ctxLabel}` });
  } else if (!distinguishable) {
    coverage.push({ checkId: "WA-AUTH-02", state: "not_tested", limitation: `Sitzung für ${ctxLabel} nicht nachweisbar gültig` });
  } else {
    const lo = await guardedRequest(role.logoutUrl, { ...opts, headers: { [h.name]: h.value } });
    const after = await guardedRequest(role.verifyUrl, { ...opts, headers: { [h.name]: h.value } });
    const stillValid = after.status === withAuth.status && Math.abs(after.body.length - withAuth.body.length) <= 50;
    const lev = `GET ${role.logoutUrl} → Status ${lo.status}\nDanach GET ${role.verifyUrl} mit demselben Sitzungswert → Status ${after.status}, ${after.body.length} Byte (vorher ${withAuth.status}, ${withAuth.body.length} Byte)`;
    if (stillValid) {
      findings.push({
        title: `Sitzung bleibt nach Logout gültig (${role.label})`, category: "Sitzungsverwaltung", kind: "vulnerability", severity: "medium", confidence: "high", checkId: "WA-AUTH-02",
        affectedUrl: role.logoutUrl, method: "GET", tool: NATIVE_TOOL, toolVersion: NATIVE_VERSION, ruleId: "WA-AUTH-02", authContext: ctxLabel, evidence: redact(lev, { knownSecrets }),
        description: "Nach dem Logout wird derselbe Sitzungswert weiterhin akzeptiert. Ein abgegriffenes Token bleibt damit bis zum Ablauf nutzbar.",
        impact: "Gestohlene oder auf geteilten Geräten verbliebene Sitzungen lassen sich nach dem Abmelden weiterverwenden.",
        remediation: "Beim Logout die Sitzung serverseitig invalidieren (Session-Store löschen bzw. Token-Sperrliste/kurze Laufzeit bei JWT).",
        limitations: "Vergleich über Statuscode und Antwortlänge.", references: ref("WA-AUTH-02"), externalLinks: [], cweId: 613,
      });
    }
    coverage.push({ checkId: "WA-AUTH-02", state: "tested", method: `Logout + erneuter Zugriff (${ctxLabel})`, evidence: redact(lev, { knownSecrets }) });
  }
  return { findings, coverage };
}

async function runRepository(spec: JobSpec, emit: Emit, signal: AbortSignal, knownSecrets: string[], log: (m: string, l?: "info" | "warn" | "error") => void, progress: (p: string, n: number) => void) {
  if (!spec.repo) {
    await emit({ type: "failed", error: "Kein Repository hinterlegt." });
    return;
  }
  progress("Werkzeuge prüfen", 2);
  const avail = await repoAdapterAvailability();
  const unavailable = avail.filter((a) => !a.available).map((a) => ({ adapter: a.name, reason: a.reason! }));
  if (unavailable.length === avail.length) {
    await emit({ type: "failed", error: "Kein Repository-Adapter verfügbar. Es wurden keine Ergebnisse erzeugt.", unavailableAdapters: unavailable });
    return;
  }
  progress("Repository klonen (fester Commit)", 5);
  const repo = await cloneRepo(spec.repo.url, spec.repo.token, spec.repo.ref, { signal, log, knownSecrets });
  const findings: RawFinding[] = [];
  const coverage: CoverageEntry[] = [];
  const versions: Record<string, string> = {};
  const executed: string[] = [`Klon von ${spec.repo.url} @ ${repo.commit}`];
  try {
    const ctx = { signal, log, knownSecrets };
    const steps: [string, string, () => Promise<void>][] = [
      ["gitleaks", "WA-REPO-01", async () => {
        versions.gitleaks = await toolVersion("gitleaks", ["version"]);
        findings.push(...(await runGitleaks(repo.dir, versions.gitleaks, ctx)));
      }],
      ["osv-scanner", "WA-REPO-02", async () => {
        versions["osv-scanner"] = await toolVersion("osv-scanner", ["--version"]);
        const r = await runOsv(repo.dir, versions["osv-scanner"], ctx);
        findings.push(...r.findings);
        if (r.lockfiles === 0) coverage.push({ checkId: "WA-REPO-02", state: "not_applicable", limitation: "Keine unterstützten Lockfiles gefunden" });
      }],
      ["semgrep", "WA-REPO-03", async () => {
        // Offline aus den Paketmetadaten (semgrep --version kann ohne Netz hängen)
        versions.semgrep = await toolVersion("python3", ["-c", "import importlib.metadata as m; print(m.version('semgrep'))"]);
        findings.push(...(await runSemgrep(repo.dir, versions.semgrep, ctx)));
      }],
    ];
    for (const [i, [name, checkId, fn]] of steps.entries()) {
      if (signal.aborted) throw new Cancelled();
      const a = avail.find((x) => x.name === name)!;
      if (!a.available) {
        coverage.push({ checkId, state: "not_tested", limitation: `Adapter nicht verfügbar: ${a.reason}` });
        continue;
      }
      progress(`${name} ausführen`, 10 + i * 28);
      try {
        await fn();
        if (!coverage.some((c) => c.checkId === checkId)) coverage.push({ checkId, state: "tested", method: name, evidence: `Commit ${repo.commit}` });
        executed.push(name);
      } catch (e) {
        if (signal.aborted) throw new Cancelled();
        log(`${name}: ${(e as Error).message}`, "error");
        coverage.push({ checkId, state: "error", limitation: redact((e as Error).message, { knownSecrets }) });
      }
    }
    progress("Ergebnisse übermitteln", 95);
    await emit({ type: "results", findings, coverage });
    await emit({ type: "complete", toolVersions: versions, executedMethods: executed, unavailableAdapters: unavailable, commitSha: repo.commit });
  } finally {
    repo.cleanup();
  }
}
