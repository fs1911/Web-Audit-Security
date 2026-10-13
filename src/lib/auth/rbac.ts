import { and, eq } from "drizzle-orm";
import type { DB } from "../db";
import { memberships, scans, sites, reports, findings } from "../db/schema";

export type Role = "owner" | "admin" | "auditor" | "viewer";

const RANK: Record<Role, number> = { viewer: 1, auditor: 2, admin: 3, owner: 4 };

/**
 * Berechtigungen:
 * - viewer: Ergebnisse und Berichte lesen
 * - auditor: zusätzlich Scans starten/abbrechen, Feststellungen bearbeiten, Berichte erzeugen
 * - admin: zusätzlich Websites, Hosts, Zugangsdaten und aktive Freigaben verwalten
 * - owner: zusätzlich Organisationseinstellungen und Mitglieder
 */
export const PERMISSIONS = {
  "site.read": "viewer",
  "scan.read": "viewer",
  "report.read": "viewer",
  "scan.start": "auditor",
  "scan.cancel": "auditor",
  "finding.update": "auditor",
  "report.create": "auditor",
  "site.manage": "admin",
  "credential.manage": "admin",
  "approval.manage": "admin",
  "org.manage": "owner",
} as const satisfies Record<string, Role>;

export type Permission = keyof typeof PERMISSIONS;

export class AccessDeniedError extends Error {
  constructor(message = "Kein Zugriff") {
    super(message);
    this.name = "AccessDeniedError";
  }
}

export function roleAllows(role: Role, perm: Permission): boolean {
  return RANK[role] >= RANK[PERMISSIONS[perm]];
}

export async function getRole(db: DB, userId: string, orgId: string): Promise<Role | null> {
  const [m] = await db.select({ role: memberships.role }).from(memberships).where(and(eq(memberships.userId, userId), eq(memberships.orgId, orgId)));
  return m?.role ?? null;
}

export async function requireOrgPermission(db: DB, userId: string, orgId: string, perm: Permission): Promise<Role> {
  const role = await getRole(db, userId, orgId);
  // Gleiche Fehlermeldung für «nicht vorhanden» und «kein Zugriff», um keine Existenz zu verraten.
  if (!role || !roleAllows(role, perm)) throw new AccessDeniedError();
  return role;
}

/** Lädt eine Ressource NUR über die Organisation des Nutzers (Mandantentrennung). */
export async function requireSite(db: DB, userId: string, siteId: string, perm: Permission) {
  if (!isUuid(siteId)) throw new AccessDeniedError();
  const [site] = await db.select().from(sites).where(eq(sites.id, siteId));
  if (!site) throw new AccessDeniedError();
  await requireOrgPermission(db, userId, site.orgId, perm);
  return site;
}

export async function requireScan(db: DB, userId: string, scanId: string, perm: Permission) {
  if (!isUuid(scanId)) throw new AccessDeniedError();
  const [scan] = await db.select().from(scans).where(eq(scans.id, scanId));
  if (!scan) throw new AccessDeniedError();
  await requireOrgPermission(db, userId, scan.orgId, perm);
  return scan;
}

export async function requireReport(db: DB, userId: string, reportId: string) {
  if (!isUuid(reportId)) throw new AccessDeniedError();
  const [r] = await db.select().from(reports).where(eq(reports.id, reportId));
  if (!r) throw new AccessDeniedError();
  await requireOrgPermission(db, userId, r.orgId, "report.read");
  return r;
}

export async function requireFinding(db: DB, userId: string, findingId: string, perm: Permission) {
  if (!isUuid(findingId)) throw new AccessDeniedError();
  const [f] = await db.select().from(findings).where(eq(findings.id, findingId));
  if (!f) throw new AccessDeniedError();
  await requireOrgPermission(db, userId, f.orgId, perm);
  return f;
}

export function isUuid(s: string): boolean {
  return /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(s);
}
