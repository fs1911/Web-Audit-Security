import { asc, eq } from "drizzle-orm";
import type { DB } from "../db";
import { coverageResults, findings, scanApprovals, scans, sites } from "../db/schema";
import { CATALOG_VERSION, CHECKS, REFERENCES, checkById } from "../catalog";
import { compareScans } from "../findings/compare";
import { SEVERITY_ORDER } from "../findings/types";
import { buildRepairPrompt } from "../findings/repair-prompt";
import { redactDeep } from "../security/redact";

export const DISCLAIMER =
  "Automatisierte technische Sicherheitsprüfung im angegebenen Umfang. Kein vollständiger Penetrationstest, keine ISO-Zertifizierung und kein Nachweis der vollständigen rechtlichen oder datenschutzrechtlichen Konformität.";

export const METRICS_EXPLANATION =
  "Kennzahlen werden getrennt ausgewiesen und nicht zu einem Gesamtwert verrechnet. Prüfabdeckung = Anzahl der im gewählten Modus implementierten Prüfpunkte mit Status «geprüft» / Anzahl aller im Modus implementierten Prüfpunkte. Befundzahlen zählen dedupliziert (gleicher Fingerprint = eine Feststellung).";

export async function loadReportData(db: DB, scanId: string) {
  const [scan] = await db.select().from(scans).where(eq(scans.id, scanId));
  if (!scan) throw new Error("Scan nicht gefunden");
  const [site] = await db.select().from(sites).where(eq(sites.id, scan.siteId));
  const fs = await db.select().from(findings).where(eq(findings.scanId, scanId)).orderBy(asc(findings.detectedAt));
  fs.sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const coverage = await db.select().from(coverageResults).where(eq(coverageResults.scanId, scanId));
  const approval = scan.approvalId ? (await db.select().from(scanApprovals).where(eq(scanApprovals.id, scan.approvalId)))[0] : null;

  let comparison = null as null | { previousScanId: string; previousDate: string; newCount: number; resolved: { title: string; affected: string }[]; unchanged: number; notRetested: number };
  if (scan.previousScanId) {
    const [prevScan] = await db.select().from(scans).where(eq(scans.id, scan.previousScanId));
    const prev = await db.select().from(findings).where(eq(findings.scanId, scan.previousScanId));
    const tested = new Set(coverage.filter((c) => c.state === "tested").map((c) => c.checkId));
    const cmp = compareScans(prev, fs, tested, new Set(Object.keys(scan.toolVersions)));
    comparison = {
      previousScanId: scan.previousScanId,
      previousDate: prevScan?.finishedAt?.toISOString() ?? "",
      newCount: cmp.newFindings.length,
      resolved: cmp.resolved.map((f) => ({ title: f.title, affected: f.affectedUrl ?? f.affectedFile ?? "" })),
      unchanged: cmp.unchanged.length,
      notRetested: cmp.notRetested.length,
    };
  }

  const modeChecks = CHECKS.filter((c) => c.implemented && c.modes.includes(scan.mode));
  const testedCount = coverage.filter((c) => c.state === "tested" && modeChecks.some((m) => m.id === c.checkId)).length;
  const counts = Object.fromEntries(SEVERITY_ORDER.map((s) => [s, fs.filter((f) => f.severity === s && f.kind !== "informational").length]));
  const byKind = { vulnerability: fs.filter((f) => f.kind === "vulnerability").length, configuration: fs.filter((f) => f.kind === "configuration").length, suspicion: fs.filter((f) => f.kind === "suspicion").length, informational: fs.filter((f) => f.kind === "informational").length };
  const notCovered = CHECKS.filter((c) => !c.implemented || !c.modes.includes(scan.mode));

  return { scan, site: site!, findings: fs, coverage, approval, comparison, modeChecks, testedCount, counts, byKind, notCovered };
}

export type ReportData = Awaited<ReturnType<typeof loadReportData>>;

export function buildJsonReport(d: ReportData) {
  const report = {
    schema: "webaudit-report/v1",
    generatedAt: new Date().toISOString(),
    disclaimer: DISCLAIMER,
    target: { site: d.site.name, baseUrl: d.site.baseUrl, environment: d.site.environment, owner: d.site.ownerName },
    scan: {
      id: d.scan.id,
      mode: d.scan.mode,
      status: d.scan.status,
      startedAt: d.scan.startedAt,
      finishedAt: d.scan.finishedAt,
      scope: d.scan.scopeSnapshot,
      limits: d.scan.limits,
      commitSha: d.scan.commitSha,
      toolVersions: d.scan.toolVersions,
      executedMethods: d.scan.executedMethods,
      unavailableAdapters: d.scan.unavailableAdapters,
      egress: d.scan.egressStats ? { allowed: d.scan.egressStats.allowed, blocked: d.scan.egressStats.blocked } : null,
      approval: d.approval ? { id: d.approval.id, profile: d.approval.profile, windowStart: d.approval.windowStart, windowEnd: d.approval.windowEnd, maxRequests: d.approval.maxRequests, requestsPerSecond: d.approval.requestsPerSecond, allowWriteEffects: d.approval.allowWriteEffects } : null,
    },
    metrics: {
      explanation: METRICS_EXPLANATION,
      coverage: { tested: d.testedCount, implementedInMode: d.modeChecks.length },
      findingsBySeverity: d.counts,
      findingsByKind: d.byKind,
    },
    comparison: d.comparison,
    catalog: { version: CATALOG_VERSION, references: REFERENCES.map((r) => ({ id: r.id, name: r.name, version: r.version, source: r.source, adoptedAt: r.adoptedAt, license: r.license })) },
    coverage: d.coverage.map((c) => ({ checkId: c.checkId, title: checkById(c.checkId)?.title, state: c.state, method: c.method, evidence: c.evidence, limitation: c.limitation })),
    notCoveredByThisMode: d.notCovered.map((c) => ({ checkId: c.id, title: c.title, automation: c.automation, implemented: c.implemented })),
    findings: d.findings.map((f) => ({
      id: f.id,
      fingerprint: f.fingerprint,
      title: f.title,
      kind: f.kind,
      category: f.category,
      severity: f.severity,
      confidence: f.confidence,
      status: f.status,
      checkId: f.checkId,
      affected: { url: f.affectedUrl, file: f.affectedFile, line: f.affectedLine, parameter: f.parameter, method: f.method, otherUrls: f.otherUrls, occurrences: f.occurrences },
      tool: { name: f.tool, version: f.toolVersion, ruleId: f.ruleId },
      authContext: f.authContext,
      detectedAt: f.detectedAt,
      evidence: f.evidence,
      description: f.description,
      impact: f.impact,
      limitations: f.limitations,
      remediation: f.remediation,
      references: f.references,
      externalLinks: f.externalLinks,
      cwe: f.cweId ? `CWE-${f.cweId}` : null,
      cvss: f.cvssVector ? { version: f.cvssVersion, vector: f.cvssVector, score: f.cvssScore, rationale: f.cvssRationale } : null,
      assignee: f.assignee,
      dueDate: f.dueDate,
      retestResult: f.retestResult,
      repairPrompt: buildRepairPrompt({ ...f, environment: d.site.environment, siteName: d.site.name }),
    })),
  };
  return redactDeep(report);
}
