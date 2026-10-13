import type { DB } from "./db";
import { auditLog } from "./db/schema";
import { redactDeep } from "./security/redact";

export type AuditAction =
  | "user.register"
  | "user.login"
  | "user.login_failed"
  | "user.logout"
  | "org.settings_changed"
  | "org.member_added"
  | "site.created"
  | "site.updated"
  | "site.authorization_confirmed"
  | "host.added"
  | "host.verified"
  | "host.verification_failed"
  | "credential.created"
  | "credential.deleted"
  | "approval.created"
  | "approval.revoked"
  | "scan.started"
  | "scan.rejected"
  | "scan.cancel_requested"
  | "scan.cancelled"
  | "scan.completed"
  | "scan.failed"
  | "finding.status_changed"
  | "report.created"
  | "report.downloaded"
  | "ai.explanation_requested"
  | "retention.purged";

export async function audit(
  db: DB,
  entry: { orgId?: string | null; userId?: string | null; action: AuditAction; targetType?: string; targetId?: string; details?: Record<string, unknown>; ip?: string | null },
): Promise<void> {
  await db.insert(auditLog).values({
    orgId: entry.orgId ?? null,
    userId: entry.userId ?? null,
    action: entry.action,
    targetType: entry.targetType,
    targetId: entry.targetId,
    details: redactDeep(entry.details ?? {}),
    ip: entry.ip ?? null,
  });
}
