import { NextResponse } from "next/server";
import { asc, eq } from "drizzle-orm";
import { getDb } from "@/lib/db";
import { scanEvents } from "@/lib/db/schema";
import { currentUser } from "@/lib/auth/current";
import { requireScan } from "@/lib/auth/rbac";

export const dynamic = "force-dynamic";

export async function GET(_req: Request, { params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await currentUser();
  if (!user) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  try {
    const db = getDb();
    const scan = await requireScan(db, user.userId, id, "scan.read");
    const events = await db.select().from(scanEvents).where(eq(scanEvents.scanId, scan.id)).orderBy(asc(scanEvents.createdAt));
    return NextResponse.json({ status: scan.status, phase: scan.phase, progress: scan.progress, events: events.slice(-30).map((e) => ({ level: e.level, message: e.message, createdAt: e.createdAt })) });
  } catch {
    return NextResponse.json({ error: "not found" }, { status: 404 });
  }
}
