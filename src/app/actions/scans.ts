"use server";

import { eq } from "drizzle-orm";
import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { getDb } from "@/lib/db";
import { findingStatusHistory, findings, organizations, sites } from "@/lib/db/schema";
import { clientIp, requireUser, requireUserAndOrg } from "@/lib/auth/current";
import { requireFinding, requireOrgPermission, requireScan, requireSite } from "@/lib/auth/rbac";
import { requestCancel, startScan, ScanRejectedError } from "@/lib/scans/service";
import { createReport } from "@/lib/reports/service";
import { audit } from "@/lib/audit";
import { aiAvailable, explainFinding, AI_MODEL } from "@/lib/ai/explain";
import type { ScanMode } from "@/lib/catalog";

const s = (fd: FormData, k: string) => String(fd.get(k) ?? "").trim();

export async function startScanAction(fd: FormData) {
  const user = await requireUser();
  const db = getDb();
  const siteId = s(fd, "siteId");
  let scanId = "";
  try {
    const site = await requireSite(db, user.userId, siteId, "scan.start");
    const mode = s(fd, "mode") as ScanMode;
    if (!["baseline", "authenticated", "active", "repository"].includes(mode)) throw new ScanRejectedError("Ungültiger Prüfmodus.");
    const scan = await startScan(
      db,
      user.userId,
      site,
      {
        siteId,
        mode,
        confirmScope: fd.get("confirmScope") === "on",
        credentialIds: fd.getAll("credentialIds").map(String),
        approvalId: s(fd, "approvalId") || undefined,
        limits: {
          maxDurationMinutes: Number(s(fd, "maxDurationMinutes")),
          maxRequests: Number(s(fd, "maxRequests")),
          requestsPerSecond: Number(s(fd, "requestsPerSecond")),
          maxDepth: Number(s(fd, "maxDepth")),
        },
      },
      await clientIp(),
    );
    scanId = scan.id;
  } catch (e) {
    redirect(`/sites/${siteId}/scan?error=${encodeURIComponent((e as Error).message)}`);
  }
  redirect(`/scans/${scanId}`);
}

export async function cancelScanAction(fd: FormData) {
  const user = await requireUser();
  const db = getDb();
  const scanId = s(fd, "scanId");
  try {
    const scan = await requireScan(db, user.userId, scanId, "scan.cancel");
    await requestCancel(db, user.userId, scan, await clientIp());
  } catch (e) {
    redirect(`/scans/${scanId}?error=${encodeURIComponent((e as Error).message)}`);
  }
  redirect(`/scans/${scanId}`);
}

export async function createReportAction(fd: FormData) {
  const user = await requireUser();
  const db = getDb();
  const scanId = s(fd, "scanId");
  const format = s(fd, "format") === "json" ? "json" : "pdf";
  let reportId = "";
  try {
    await requireScan(db, user.userId, scanId, "report.create");
    reportId = (await createReport(db, scanId, format, user.userId)).id;
  } catch (e) {
    redirect(`/scans/${scanId}?error=${encodeURIComponent((e as Error).message)}`);
  }
  redirect(`/scans/${scanId}?ok=${encodeURIComponent(`${format.toUpperCase()}-Bericht erstellt.`)}#berichte`);
  void reportId;
}

export async function updateFindingAction(fd: FormData) {
  const user = await requireUser();
  const db = getDb();
  const id = s(fd, "findingId");
  try {
    const f = await requireFinding(db, user.userId, id, "finding.update");
    const status = s(fd, "status") as typeof f.status;
    if (!["open", "in_progress", "fixed", "false_positive", "risk_accepted"].includes(status)) throw new Error("Ungültiger Status.");
    const comment = s(fd, "comment");
    if ((status === "false_positive" || status === "risk_accepted") && comment.length < 5) throw new Error("Für «Fehlalarm» und «Risiko akzeptiert» ist eine Begründung erforderlich.");
    const due = s(fd, "dueDate");
    await db.update(findings).set({ status, assignee: s(fd, "assignee") || null, dueDate: due ? new Date(due) : null }).where(eq(findings.id, f.id));
    if (status !== f.status) {
      await db.insert(findingStatusHistory).values({ findingId: f.id, fromStatus: f.status, toStatus: status, comment: comment || null, changedBy: user.userId });
      await audit(db, { orgId: f.orgId, userId: user.userId, action: "finding.status_changed", targetType: "finding", targetId: f.id, details: { from: f.status, to: status, comment }, ip: await clientIp() });
    }
  } catch (e) {
    redirect(`/findings/${id}?error=${encodeURIComponent((e as Error).message)}`);
  }
  revalidatePath(`/findings/${id}`);
  redirect(`/findings/${id}?ok=${encodeURIComponent("Gespeichert.")}`);
}

export async function explainFindingAction(fd: FormData) {
  const user = await requireUser();
  const db = getDb();
  const id = s(fd, "findingId");
  let msg = "";
  let ok = false;
  try {
    const f = await requireFinding(db, user.userId, id, "finding.update");
    const [org] = await db.select().from(organizations).where(eq(organizations.id, f.orgId));
    if (!org?.aiEnabled) throw new Error("Externe KI-Verarbeitung ist für diese Organisation deaktiviert (Einstellungen).");
    if (!aiAvailable()) throw new Error("Kein KI-Schlüssel konfiguriert. Erklärungen und Reparaturprompts stehen weiterhin als Vorlagen zur Verfügung.");
    const [site] = await db.select().from(sites).where(eq(sites.id, f.siteId));
    await audit(db, { orgId: f.orgId, userId: user.userId, action: "ai.explanation_requested", targetType: "finding", targetId: f.id, details: { model: AI_MODEL } });
    const out = await explainFinding({ ...f, environment: site!.environment, siteName: site!.name });
    await db.update(findings).set({ aiExplanation: { model: AI_MODEL, createdAt: new Date().toISOString(), ...out } }).where(eq(findings.id, f.id));
    ok = true;
    msg = "KI-Erklärung erstellt.";
  } catch (e) {
    msg = (e as Error).message;
  }
  redirect(`/findings/${id}?${ok ? "ok" : "error"}=${encodeURIComponent(msg)}`);
}

export async function updateSettingsAction(fd: FormData) {
  const { user, org } = await requireUserAndOrg();
  const db = getDb();
  try {
    await requireOrgPermission(db, user.userId, org.id, "org.manage");
    const aiEnabled = fd.get("aiEnabled") === "on";
    const retentionDays = Math.min(3650, Math.max(7, Number(s(fd, "retentionDays")) || 180));
    await db.update(organizations).set({ aiEnabled, retentionDays }).where(eq(organizations.id, org.id));
    await audit(db, { orgId: org.id, userId: user.userId, action: "org.settings_changed", details: { aiEnabled, retentionDays }, ip: await clientIp() });
  } catch (e) {
    redirect(`/settings?error=${encodeURIComponent((e as Error).message)}`);
  }
  redirect(`/settings?ok=${encodeURIComponent("Einstellungen gespeichert.")}`);
}
