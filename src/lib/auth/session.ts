import { and, count, eq, gt, sql } from "drizzle-orm";
import type { DB } from "../db";
import { auditLog, memberships, organizations, sessions, users } from "../db/schema";
import { randomToken, sha256 } from "../security/crypto";

/** Für Sperrlogik: nur Hash der E-Mail im Audit-Log (keine Klartext-Adresse). */
const emailKey = (email: string) => sha256(`login:${email}`).slice(0, 32);
import { hashPassword, validatePasswordStrength, verifyPassword } from "./password";
import { audit } from "../audit";

export const SESSION_COOKIE = "wa_session";
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

export async function createSession(db: DB, userId: string): Promise<{ token: string; expiresAt: Date }> {
  const token = randomToken(32);
  const expiresAt = new Date(Date.now() + SESSION_TTL_MS);
  await db.insert(sessions).values({ id: sha256(token), userId, expiresAt });
  return { token, expiresAt };
}

export async function validateSessionToken(db: DB, token: string | undefined | null) {
  if (!token || token.length > 128) return null;
  const [row] = await db
    .select({ userId: users.id, email: users.email, name: users.name, expiresAt: sessions.expiresAt })
    .from(sessions)
    .innerJoin(users, eq(users.id, sessions.userId))
    .where(and(eq(sessions.id, sha256(token)), gt(sessions.expiresAt, new Date())));
  return row ?? null;
}

export async function deleteSession(db: DB, token: string): Promise<void> {
  await db.delete(sessions).where(eq(sessions.id, sha256(token)));
}

export async function registerUser(db: DB, input: { email: string; name: string; password: string; orgName: string }) {
  const email = input.email.trim().toLowerCase();
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) throw new Error("Bitte eine gültige E-Mail-Adresse angeben.");
  if (!input.name.trim()) throw new Error("Bitte einen Namen angeben.");
  if (!input.orgName.trim()) throw new Error("Bitte einen Organisationsnamen angeben.");
  const pwErr = validatePasswordStrength(input.password);
  if (pwErr) throw new Error(pwErr);
  const [existing] = await db.select({ id: users.id }).from(users).where(sql`lower(${users.email}) = ${email}`);
  if (existing) throw new Error("Für diese E-Mail-Adresse besteht bereits ein Konto.");
  const passwordHash = await hashPassword(input.password);
  return db.transaction(async (tx) => {
    const [user] = await tx.insert(users).values({ email, name: input.name.trim(), passwordHash }).returning();
    const [org] = await tx.insert(organizations).values({ name: input.orgName.trim() }).returning();
    await tx.insert(memberships).values({ orgId: org!.id, userId: user!.id, role: "owner" });
    await audit(tx as unknown as DB, { orgId: org!.id, userId: user!.id, action: "user.register", targetType: "user", targetId: user!.id });
    return { user: user!, org: org! };
  });
}

const MAX_FAILED = 5;
const WINDOW_MS = 15 * 60 * 1000;

export async function authenticate(db: DB, emailRaw: string, password: string, ip: string | null) {
  const email = emailRaw.trim().toLowerCase();
  const [{ value: failed } = { value: 0 }] = await db
    .select({ value: count() })
    .from(auditLog)
    .where(and(eq(auditLog.action, "user.login_failed"), sql`${auditLog.details}->>'emailKey' = ${emailKey(email)}`, gt(auditLog.createdAt, new Date(Date.now() - WINDOW_MS))));
  if (failed >= MAX_FAILED) {
    throw new Error("Zu viele fehlgeschlagene Anmeldeversuche. Bitte in 15 Minuten erneut versuchen.");
  }
  const [user] = await db.select().from(users).where(sql`lower(${users.email}) = ${email}`);
  // Auch bei unbekanntem Benutzer hashen, um Timing-Unterschiede zu verringern.
  const ok = user ? await verifyPassword(password, user.passwordHash) : (await hashPassword(password), false);
  if (!user || !ok) {
    await audit(db, { action: "user.login_failed", details: { emailKey: emailKey(email) }, ip });
    throw new Error("E-Mail oder Passwort ist falsch.");
  }
  await audit(db, { userId: user.id, action: "user.login", ip });
  return user;
}

export async function userOrgs(db: DB, userId: string) {
  return db
    .select({ id: organizations.id, name: organizations.name, role: memberships.role, aiEnabled: organizations.aiEnabled, retentionDays: organizations.retentionDays })
    .from(memberships)
    .innerJoin(organizations, eq(organizations.id, memberships.orgId))
    .where(eq(memberships.userId, userId));
}
