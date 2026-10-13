import { and, desc, eq, inArray, isNotNull, lt, ne, sql } from "drizzle-orm";
import type { DB } from "../db";
import { coverageResults, credentials, findings, scanApprovals, scanEvents, scanJobs, scans, siteHosts, sites } from "../db/schema";
import { audit } from "../audit";
import { clampLimits, type JobSpec, type RunnerEvent } from "../jobs/spec";
import { normalizeScope, checkScope, type Scope } from "../security/scope";
import { loadPolicy, normalizeHostname } from "../security/netguard";
import { decryptSecret, jobToken } from "../security/crypto";
import { dedupeFindings } from "../findings/fingerprint";
import { redact, redactDeep } from "../security/redact";
import { checksForMode, type ScanMode } from "../catalog";
import type { ScanLimits } from "../db/schema";

export class ScanRejectedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ScanRejectedError";
  }
}

export async function verifiedScope(db: DB, site: typeof sites.$inferSelect): Promise<Scope> {
  const hosts = await db.select().from(siteHosts).where(and(eq(siteHosts.siteId, site.id), isNotNull(siteHosts.verifiedAt)));
  return normalizeScope({ hosts: hosts.map((h) => h.host), includePaths: site.includePaths, excludePaths: site.excludePaths });
}

export type StartScanInput = {
  siteId: string;
  mode: ScanMode;
  limits?: Partial<ScanLimits>;
  credentialIds?: string[];
  approvalId?: string;
  confirmScope: boolean;
};

/**
 * Deterministische Durchsetzung aller Startbedingungen (ausserhalb jedes Sprachmodells).
 */
export async function startScan(db: DB, userId: string, site: typeof sites.$inferSelect, input: StartScanInput, ip?: string | null) {
  const reject = async (reason: string): Promise<never> => {
    await audit(db, { orgId: site.orgId, userId, action: "scan.rejected", targetType: "site", targetId: site.id, details: { mode: input.mode, reason }, ip });
    throw new ScanRejectedError(reason);
  };
  if (!input.confirmScope) await reject("Prüfumfang und Limits wurden nicht bestätigt.");
  if (!site.authorizationConfirmedAt) await reject("Die Prüfberechtigung für diese Website wurde nicht bestätigt.");

  const scope = await verifiedScope(db, site);
  if (input.mode !== "repository") {
    if (scope.hosts.length === 0) await reject("Kein Host dieser Website ist technisch verifiziert.");
    const baseHost = normalizeHostname(new URL(site.baseUrl).hostname);
    if (!scope.hosts.includes(baseHost)) await reject(`Der Host der Basis-URL (${baseHost}) ist nicht verifiziert.`);
    const d = checkScope(site.baseUrl, scope, loadPolicy(), { stateChangingGuard: false });
    if (!d.inScope) await reject(`Basis-URL nicht im Scope: ${d.reason}`);
  } else if (!site.repoUrl) {
    await reject("Für den Repository-Check ist kein GitHub-Repository hinterlegt.");
  }

  // Parallelitätslimit: pro Website höchstens ein laufender Scan, pro Organisation konfigurierbar
  const active = await db.select({ id: scans.id, siteId: scans.siteId }).from(scans).where(and(eq(scans.orgId, site.orgId), inArray(scans.status, ["queued", "running", "cancel_requested"])));
  if (active.some((s) => s.siteId === site.id)) await reject("Für diese Website läuft bereits ein Scan.");
  const orgMax = Number(process.env.MAX_CONCURRENT_SCANS_PER_ORG ?? 2);
  if (active.length >= orgMax) await reject(`Maximal ${orgMax} gleichzeitige Scans pro Organisation.`);

  let limits = clampLimits(input.limits ?? {});
  let approvalId: string | null = null;
  if (input.mode === "active") {
    if (process.env.ENABLE_ACTIVE_SCANS !== "true") await reject("Aktive Prüfungen sind auf dieser Installation deaktiviert (ENABLE_ACTIVE_SCANS).");
    if (!input.approvalId) await reject("Für aktive Prüfungen ist eine gesonderte Freigabe erforderlich.");
    const [ap] = await db.select().from(scanApprovals).where(and(eq(scanApprovals.id, input.approvalId!), eq(scanApprovals.siteId, site.id)));
    if (!ap || ap.revokedAt) await reject("Freigabe nicht gefunden oder widerrufen.");
    const now = Date.now();
    if (now < ap!.windowStart.getTime() || now > ap!.windowEnd.getTime()) await reject("Die Freigabe ist ausserhalb ihres Zeitfensters.");
    if (ap!.targetUrl !== site.baseUrl) await reject("Die Freigabe gilt für ein anderes Ziel.");
    if (site.environment === "production" && process.env.ALLOW_ACTIVE_ON_PRODUCTION !== "true") {
      await reject("Aktive Prüfungen auf Produktionsumgebungen sind gesperrt. Empfehlung: Staging mit Testdaten.");
    }
    // Limits der Freigabe sind verbindliche Obergrenzen
    limits = { ...limits, maxRequests: Math.min(limits.maxRequests, ap!.maxRequests), requestsPerSecond: Math.min(limits.requestsPerSecond, ap!.requestsPerSecond), maxDurationMinutes: Math.min(limits.maxDurationMinutes, Math.max(1, Math.floor((ap!.windowEnd.getTime() - now) / 60000))) };
    approvalId = ap!.id;
  }
  let credentialIds: string[] = [];
  if (input.mode === "authenticated" || input.mode === "repository") {
    const wanted = input.credentialIds ?? [];
    const rows = wanted.length ? await db.select().from(credentials).where(and(eq(credentials.siteId, site.id), inArray(credentials.id, wanted))) : [];
    if (input.mode === "authenticated") {
      const roles = rows.filter((r) => r.kind === "header" || r.kind === "cookie");
      if (roles.length === 0) await reject("Für den authentifizierten Check muss mindestens ein Testzugang gewählt werden.");
      credentialIds = roles.map((r) => r.id);
    } else {
      credentialIds = rows.filter((r) => r.kind === "github_token").map((r) => r.id).slice(0, 1);
    }
  }

  const [prev] = await db.select({ id: scans.id }).from(scans).where(and(eq(scans.siteId, site.id), eq(scans.mode, input.mode), eq(scans.status, "completed"))).orderBy(desc(scans.createdAt)).limit(1);
  const [scan] = await db
    .insert(scans)
    .values({ orgId: site.orgId, siteId: site.id, mode: input.mode, limits, scopeSnapshot: scope, approvalId, credentialIds, startedBy: userId, previousScanId: prev?.id ?? null, phase: "In Warteschlange" })
    .returning();
  await db.insert(scanJobs).values({ scanId: scan!.id });
  await audit(db, { orgId: site.orgId, userId, action: "scan.started", targetType: "scan", targetId: scan!.id, details: { mode: input.mode, limits, scope, approvalId }, ip });
  return scan!;
}

export async function requestCancel(db: DB, userId: string, scan: typeof scans.$inferSelect, ip?: string | null) {
  if (scan.status === "queued") {
    await db.update(scans).set({ status: "cancelled", phase: "Abgebrochen (vor Start)", finishedAt: new Date() }).where(eq(scans.id, scan.id));
    await db.update(scanJobs).set({ state: "done" }).where(eq(scanJobs.scanId, scan.id));
    await audit(db, { orgId: scan.orgId, userId, action: "scan.cancelled", targetType: "scan", targetId: scan.id, ip });
    return;
  }
  if (scan.status !== "running") throw new ScanRejectedError("Der Scan läuft nicht mehr.");
  await db.update(scans).set({ status: "cancel_requested", phase: "Abbruch angefordert" }).where(eq(scans.id, scan.id));
  await audit(db, { orgId: scan.orgId, userId, action: "scan.cancel_requested", targetType: "scan", targetId: scan.id, ip });
  // Direkter Abbruch beim Runner (zusätzlich zum Abbruchsignal in der nächsten Callback-Antwort)
  const [job] = await db.select().from(scanJobs).where(eq(scanJobs.scanId, scan.id));
  if (job?.runnerRef && process.env.RUNNER_URL) {
    await fetch(`${process.env.RUNNER_URL}/jobs/${job.id}/cancel`, { method: "POST", headers: { authorization: `Bearer ${process.env.RUNNER_SHARED_SECRET}` }, signal: AbortSignal.timeout(5000) }).catch(() => undefined);
  }
}

export async function buildJobSpec(db: DB, jobId: string, scan: typeof scans.$inferSelect): Promise<JobSpec> {
  const [site] = await db.select().from(sites).where(eq(sites.id, scan.siteId));
  if (!site) throw new Error("Website nicht gefunden");
  const creds = scan.credentialIds.length ? await db.select().from(credentials).where(inArray(credentials.id, scan.credentialIds)) : [];
  const callbackBase = process.env.APP_INTERNAL_URL ?? process.env.APP_URL ?? "http://127.0.0.1:3000";
  const spec: JobSpec = {
    jobId,
    scanId: scan.id,
    mode: scan.mode,
    siteName: site.name,
    environment: site.environment,
    baseUrl: site.baseUrl,
    scope: scan.scopeSnapshot,
    limits: scan.limits,
    callbackUrl: `${callbackBase}/api/internal/jobs/${jobId}/events`,
    callbackToken: jobToken(jobId),
    allowInvalidCerts: process.env.NODE_ENV !== "production" && process.env.WEBAUDIT_ALLOW_INVALID_CERTS === "true",
  };
  if (scan.mode === "authenticated") {
    spec.auth = {
      roles: creds
        .filter((c) => c.kind !== "github_token")
        .map((c) => ({ label: c.label, kind: c.kind as "header" | "cookie", headerName: c.headerName ?? undefined, value: decryptSecret(c.encryptedValue), verifyUrl: c.verifyUrl ?? undefined, logoutUrl: c.logoutUrl ?? undefined })),
    };
  }
  if (scan.mode === "repository") {
    const tok = creds.find((c) => c.kind === "github_token");
    spec.repo = { url: site.repoUrl!, token: tok ? decryptSecret(tok.encryptedValue) : undefined };
  }
  if (scan.mode === "active" && scan.approvalId) {
    const [ap] = await db.select().from(scanApprovals).where(eq(scanApprovals.id, scan.approvalId));
    spec.active = { approvalId: ap!.id, windowEnd: ap!.windowEnd.toISOString(), profile: "webaudit-safe", allowWriteEffects: ap!.allowWriteEffects };
  }
  return spec;
}

async function scanSecrets(db: DB, credentialIds: string[]): Promise<string[]> {
  if (!credentialIds.length) return [];
  const rows = await db.select().from(credentials).where(inArray(credentials.id, credentialIds));
  const out: string[] = [];
  for (const r of rows) {
    try {
      const v = decryptSecret(r.encryptedValue);
      out.push(v);
      // Auch den reinen Token-Teil (ohne «Bearer »/Cookie-Namen) entfernen
      const m = v.match(/^(?:Bearer|Basic|Token)\s+(.+)$/i) ?? v.match(/^[^=;]+=([^;]+)/);
      if (m?.[1]) out.push(m[1]);
    } catch {
      /* nicht entschlüsselbar – ignorieren */
    }
  }
  return out;
}

/** Verarbeitet ein signiertes Runner-Ereignis. Rückgabe: soll der Runner abbrechen? */
export async function handleRunnerEvent(db: DB, jobId: string, event: RunnerEvent): Promise<{ cancel: boolean; status: number }> {
  const [job] = await db.select().from(scanJobs).where(eq(scanJobs.id, jobId));
  if (!job) return { cancel: true, status: 404 };
  const [scan] = await db.select().from(scans).where(eq(scans.id, job.scanId));
  if (!scan) return { cancel: true, status: 404 };
  if (["completed", "failed", "cancelled"].includes(scan.status)) return { cancel: true, status: 409 };
  const cancel = scan.status === "cancel_requested";
  const now = new Date();
  // Zweite Verteidigungslinie: hinterlegte Zugangsdaten dieses Scans serverseitig aus allen Texten entfernen
  const knownSecrets = await scanSecrets(db, scan.credentialIds);

  switch (event.type) {
    case "heartbeat":
      await db.update(scans).set({ lastHeartbeatAt: now }).where(eq(scans.id, scan.id));
      break;
    case "progress": {
      const set: Partial<typeof scans.$inferInsert> = { lastHeartbeatAt: now };
      if (event.phase && !cancel) set.phase = event.phase.slice(0, 200);
      if (event.progress >= 0) set.progress = event.progress;
      await db.update(scans).set(set).where(eq(scans.id, scan.id));
      if (event.message) await db.insert(scanEvents).values({ scanId: scan.id, level: event.level ?? "info", message: redact(event.message, { maxLength: 1000, knownSecrets }) });
      break;
    }
    case "results": {
      if (cancel) break;
      const [site] = await db.select().from(sites).where(eq(sites.id, scan.siteId));
      const deduped = dedupeFindings(redactDeep(event.findings, { knownSecrets }));
      if (deduped.length) {
        await db.insert(findings).values(
          deduped.map((f) => ({
            orgId: scan.orgId,
            siteId: scan.siteId,
            scanId: scan.id,
            fingerprint: f.fingerprint,
            title: f.title.slice(0, 300),
            category: f.category,
            kind: f.kind,
            severity: f.severity,
            confidence: f.confidence,
            checkId: f.checkId,
            affectedUrl: f.affectedUrl,
            affectedFile: f.affectedFile,
            affectedLine: f.affectedLine,
            parameter: f.parameter,
            method: f.method,
            tool: f.tool,
            toolVersion: f.toolVersion,
            ruleId: f.ruleId,
            authContext: f.authContext,
            evidence: redact(f.evidence, { maxLength: 4000, knownSecrets }),
            description: f.description,
            impact: f.impact,
            prerequisites: f.prerequisites,
            limitations: f.limitations,
            remediation: f.remediation,
            references: f.references,
            externalLinks: f.externalLinks,
            cweId: f.cweId,
            cvssVersion: f.cvss?.version,
            cvssVector: f.cvss?.vector,
            cvssScore: f.cvss?.score || null,
            cvssRationale: f.cvss?.rationale,
            occurrences: f.occurrences,
            otherUrls: f.otherUrls,
            assignee: site?.ownerName,
          })),
        );
      }
      // Abdeckung: alle Prüfpunkte des Modus erfassen; nicht gemeldete bleiben ausdrücklich «nicht geprüft»
      const reported = new Map<string, (typeof event.coverage)[number]>();
      for (const c of event.coverage) {
        const prevEntry = reported.get(c.checkId);
        // «tested» hat Vorrang vor mehrfachen Teilmeldungen
        if (!prevEntry || (prevEntry.state !== "tested" && c.state === "tested")) reported.set(c.checkId, c);
      }
      const rows = checksForMode(scan.mode).map((chk) => {
        const c = reported.get(chk.id);
        return { scanId: scan.id, checkId: chk.id, state: c?.state ?? ("not_tested" as const), method: c?.method, evidence: c?.evidence ? redact(c.evidence, { maxLength: 1500, knownSecrets }) : null, limitation: c?.limitation ?? (c ? null : "Vom Runner nicht ausgeführt") };
      });
      for (const [id, c] of reported) if (!rows.some((r) => r.checkId === id)) rows.push({ scanId: scan.id, checkId: id, state: c.state, method: c.method, evidence: c.evidence ?? null, limitation: c.limitation ?? null });
      if (rows.length) await db.insert(coverageResults).values(rows).onConflictDoNothing();
      break;
    }
    case "complete": {
      const status = event.cancelled || cancel ? "cancelled" : "completed";
      if (status === "cancelled") {
        // Teilergebnisse eines abgebrochenen Scans werden verworfen, damit nichts als «geprüft» erscheint.
        await db.delete(findings).where(eq(findings.scanId, scan.id));
        await db.delete(coverageResults).where(eq(coverageResults.scanId, scan.id));
      }
      await db
        .update(scans)
        .set({ status, phase: status === "cancelled" ? "Abgebrochen" : "Abgeschlossen", progress: status === "completed" ? 100 : scan.progress, finishedAt: now, toolVersions: event.toolVersions, executedMethods: event.executedMethods, unavailableAdapters: event.unavailableAdapters, egressStats: event.egressStats ?? null, commitSha: event.commitSha ?? null })
        .where(eq(scans.id, scan.id));
      await db.update(scanJobs).set({ state: "done" }).where(eq(scanJobs.id, jobId));
      await audit(db, { orgId: scan.orgId, action: status === "cancelled" ? "scan.cancelled" : "scan.completed", targetType: "scan", targetId: scan.id });
      if (status === "completed") await applyRetest(db, scan.id);
      return { cancel: false, status: 200 };
    }
    case "failed": {
      await db.update(scans).set({ status: "failed", phase: "Fehlgeschlagen", error: redact(event.error, { maxLength: 2000, knownSecrets }), finishedAt: now, unavailableAdapters: event.unavailableAdapters ?? [] }).where(eq(scans.id, scan.id));
      await db.update(scanJobs).set({ state: "done" }).where(eq(scanJobs.id, jobId));
      await db.delete(findings).where(eq(findings.scanId, scan.id));
      await audit(db, { orgId: scan.orgId, action: "scan.failed", targetType: "scan", targetId: scan.id, details: { error: redact(event.error, { maxLength: 500, knownSecrets }) } });
      return { cancel: false, status: 200 };
    }
  }
  return { cancel, status: 200 };
}

/**
 * Nachprüfung: Offene Feststellungen früherer Scans derselben Website und desselben Modus,
 * die im neuen Scan geprüft, aber nicht mehr gefunden wurden, erhalten ein Nachprüfungsergebnis.
 * Status-Übernahme: Bearbeitungsstatus/Verantwortliche werden auf wiedergefundene Feststellungen übertragen.
 */
export async function applyRetest(db: DB, scanId: string) {
  const [scan] = await db.select().from(scans).where(eq(scans.id, scanId));
  if (!scan?.previousScanId) return;
  const prev = await db.select().from(findings).where(eq(findings.scanId, scan.previousScanId));
  const cur = await db.select().from(findings).where(eq(findings.scanId, scanId));
  const tested = new Set((await db.select().from(coverageResults).where(and(eq(coverageResults.scanId, scanId), eq(coverageResults.state, "tested")))).map((c) => c.checkId));
  const curFp = new Map(cur.map((f) => [f.fingerprint, f]));
  const date = new Date().toISOString().slice(0, 10);
  for (const p of prev) {
    const again = curFp.get(p.fingerprint);
    if (again) {
      await db.update(findings).set({ status: p.status === "fixed" ? "open" : p.status, assignee: p.assignee, dueDate: p.dueDate, retestResult: p.status === "fixed" ? `Nachprüfung ${date}: als behoben markiert, aber erneut gefunden` : `Nachprüfung ${date}: weiterhin vorhanden` }).where(eq(findings.id, again.id));
    } else if (p.checkId && tested.has(p.checkId)) {
      await db.update(findings).set({ retestResult: `Nachprüfung ${date}: im Scan ${scanId.slice(0, 8)} nicht mehr gefunden` }).where(eq(findings.id, p.id));
    }
  }
}

/** Dispatcher-Hilfen */
export async function claimNextJob(db: DB) {
  const rows = await db.execute(sql`
    UPDATE scan_jobs SET state = 'claimed', claimed_at = now(), attempts = attempts + 1
    WHERE id = (
      SELECT j.id FROM scan_jobs j JOIN scans s ON s.id = j.scan_id
      WHERE j.state = 'pending' AND s.status = 'queued'
      ORDER BY j.created_at FOR UPDATE OF j SKIP LOCKED LIMIT 1
    ) RETURNING id, scan_id`);
  const r = (rows as unknown as { id: string; scan_id: string }[])[0];
  return r ? { jobId: r.id, scanId: r.scan_id } : null;
}

export async function failStaleScans(db: DB, staleMs = 3 * 60_000) {
  const cutoff = new Date(Date.now() - staleMs);
  const stale = await db.select().from(scans).where(and(inArray(scans.status, ["running", "cancel_requested"]), lt(scans.lastHeartbeatAt, cutoff)));
  for (const s of stale) {
    const status = s.status === "cancel_requested" ? "cancelled" : "failed";
    await db.update(scans).set({ status, phase: status === "cancelled" ? "Abgebrochen" : "Fehlgeschlagen", error: status === "failed" ? "Keine Rückmeldung vom Scan-Worker (Zeitüberschreitung). Es wurden keine Ergebnisse übernommen." : null, finishedAt: new Date() }).where(and(eq(scans.id, s.id), ne(scans.status, "completed")));
    await db.delete(findings).where(eq(findings.scanId, s.id));
    await db.update(scanJobs).set({ state: "done" }).where(eq(scanJobs.scanId, s.id));
  }
  // Harte Laufzeitgrenze
  const overdue = await db.select().from(scans).where(eq(scans.status, "running"));
  for (const s of overdue) {
    if (s.startedAt && Date.now() - s.startedAt.getTime() > (s.limits.maxDurationMinutes + 10) * 60_000) {
      await db.update(scans).set({ status: "cancel_requested", phase: "Zeitlimit überschritten – Abbruch angefordert" }).where(eq(scans.id, s.id));
    }
  }
  return stale.length;
}
