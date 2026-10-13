import type { DB } from "../db";
import { reports } from "../db/schema";
import { getStore } from "../storage";
import { sha256 } from "../security/crypto";
import { audit } from "../audit";
import { buildJsonReport, loadReportData } from "./data";
import { buildPdfReport } from "./pdf";

export async function createReport(db: DB, scanId: string, format: "pdf" | "json", userId: string | null) {
  const data = await loadReportData(db, scanId);
  if (data.scan.status !== "completed") throw new Error("Berichte können nur für abgeschlossene Scans erstellt werden.");
  const bytes = format === "pdf" ? await buildPdfReport(data) : new TextEncoder().encode(JSON.stringify(buildJsonReport(data), null, 2));
  const key = `orgs/${data.scan.orgId}/scans/${scanId}/report-${Date.now()}.${format}`;
  await getStore().put(key, bytes, format === "pdf" ? "application/pdf" : "application/json");
  const [row] = await db
    .insert(reports)
    .values({ orgId: data.scan.orgId, scanId, format, objectKey: key, sha256: sha256(Buffer.from(bytes)), sizeBytes: bytes.length, createdBy: userId })
    .returning();
  await audit(db, { orgId: data.scan.orgId, userId, action: "report.created", targetType: "report", targetId: row!.id, details: { format, scanId } });
  return row!;
}
