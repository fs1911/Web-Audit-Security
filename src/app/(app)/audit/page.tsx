import { desc, eq } from "drizzle-orm";
import { getDb } from "@/lib/db";
import { auditLog, users } from "@/lib/db/schema";
import { requireUserAndOrg } from "@/lib/auth/current";
import { requireOrgPermission } from "@/lib/auth/rbac";
import { fmtDate } from "@/components/ui";

export default async function AuditPage() {
  const { user, org } = await requireUserAndOrg();
  const db = getDb();
  await requireOrgPermission(db, user.userId, org.id, "site.read");
  const rows = await db
    .select({ id: auditLog.id, action: auditLog.action, targetType: auditLog.targetType, targetId: auditLog.targetId, details: auditLog.details, createdAt: auditLog.createdAt, ip: auditLog.ip, userName: users.name })
    .from(auditLog)
    .leftJoin(users, eq(users.id, auditLog.userId))
    .where(eq(auditLog.orgId, org.id))
    .orderBy(desc(auditLog.createdAt))
    .limit(300);
  return (
    <div className="space-y-4">
      <h1 className="h1">Audit-Log</h1>
      <p className="text-sm text-slate-600">Freigaben, Starts, Änderungen und Abbrüche. Sensible Werte sind entfernt.</p>
      <div className="card overflow-x-auto">
        <table className="table">
          <thead><tr><th>Zeit</th><th>Person</th><th>Aktion</th><th>Ziel</th><th>Details</th></tr></thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id}>
                <td className="whitespace-nowrap">{fmtDate(r.createdAt)}</td>
                <td>{r.userName ?? "System"}</td>
                <td className="font-mono text-xs">{r.action}</td>
                <td className="text-xs">{r.targetType} {r.targetId?.slice(0, 8)}</td>
                <td className="max-w-lg break-all font-mono text-xs">{JSON.stringify(r.details)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
