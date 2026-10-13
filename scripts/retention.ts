import { and, eq, inArray, lt } from "drizzle-orm";
import { closeDb, getDb } from "../src/lib/db";
import { organizations, reports, scans } from "../src/lib/db/schema";
import { getStore } from "../src/lib/storage";
import { audit } from "../src/lib/audit";

/** Löscht Scans (inkl. Feststellungen, Abdeckung, Ereignisse per Cascade) und Berichte älter als die Aufbewahrungsfrist. */
const db = getDb();
const store = getStore();
for (const org of await db.select().from(organizations)) {
  const cutoff = new Date(Date.now() - org.retentionDays * 86400_000);
  const old = await db.select({ id: scans.id }).from(scans).where(and(eq(scans.orgId, org.id), lt(scans.createdAt, cutoff), inArray(scans.status, ["completed", "failed", "cancelled"])));
  if (!old.length) continue;
  const ids = old.map((s) => s.id);
  for (const r of await db.select().from(reports).where(inArray(reports.scanId, ids))) await store.delete(r.objectKey);
  await db.delete(scans).where(inArray(scans.id, ids));
  await audit(db, { orgId: org.id, action: "retention.purged", details: { scans: ids.length, cutoff: cutoff.toISOString() } });
  console.log(`${org.name}: ${ids.length} Scan(s) gelöscht`);
}
await closeDb();
