import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { currentUser } from "@/lib/auth/current";
import { requireReport } from "@/lib/auth/rbac";
import { getStore } from "@/lib/storage";
import { audit } from "@/lib/audit";

export const dynamic = "force-dynamic";

/** Report-Download nur nach Berechtigungsprüfung; der Objektspeicher ist nie öffentlich. */
export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  const db = getDb();
  let report;
  try {
    report = await requireReport(db, user.userId, id);
  } catch {
    return NextResponse.json({ error: "not found" }, { status: 404 });
  }
  const bytes = await getStore().get(report.objectKey);
  await audit(db, { orgId: report.orgId, userId: user.userId, action: "report.downloaded", targetType: "report", targetId: report.id });
  return new NextResponse(Buffer.from(bytes), {
    headers: {
      "content-type": report.format === "pdf" ? "application/pdf" : "application/json; charset=utf-8",
      "content-disposition": `attachment; filename="webaudit-report-${report.scanId.slice(0, 8)}.${report.format}"`,
      "cache-control": "private, no-store",
      "x-content-type-options": "nosniff",
    },
  });
}
