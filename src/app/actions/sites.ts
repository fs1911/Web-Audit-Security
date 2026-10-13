"use server";

import { and, eq } from "drizzle-orm";
import { redirect } from "next/navigation";
import { revalidatePath } from "next/cache";
import { getDb } from "@/lib/db";
import { credentials, scanApprovals, siteHosts, sites } from "@/lib/db/schema";
import { clientIp, requireUser, requireUserAndOrg } from "@/lib/auth/current";
import { requireOrgPermission, requireSite } from "@/lib/auth/rbac";
import { audit } from "@/lib/audit";
import { loadPolicy, NetguardError, normalizeHostname, validateUrl } from "@/lib/security/netguard";
import { normalizeScope } from "@/lib/security/scope";
import { encryptSecret, randomToken } from "@/lib/security/crypto";
import { verifyDnsTxt, verifyFile } from "@/lib/verification";
import { parseGithubUrl } from "@/lib/github";

const s = (fd: FormData, k: string) => String(fd.get(k) ?? "").trim();
const lines = (v: string) => v.split(/[\n,]/).map((x) => x.trim()).filter(Boolean);
const fail = (path: string, msg: string): never => redirect(`${path}${path.includes("?") ? "&" : "?"}error=${encodeURIComponent(msg)}`);

export async function createSiteAction(fd: FormData) {
  const { user, org } = await requireUserAndOrg();
  const db = getDb();
  let siteId = "";
  try {
    await requireOrgPermission(db, user.userId, org.id, "site.manage");
    const name = s(fd, "name");
    const baseUrl = s(fd, "baseUrl");
    const environment = s(fd, "environment") as "production" | "staging" | "development";
    const ownerName = s(fd, "ownerName");
    if (!name || !ownerName) throw new Error("Name und verantwortliche Person sind Pflichtfelder.");
    if (!["production", "staging", "development"].includes(environment)) throw new Error("Ungültige Umgebung.");
    if (fd.get("authorized") !== "on") throw new Error("Ohne Bestätigung der Prüfberechtigung kann keine Website angelegt werden.");
    const statement = s(fd, "authorizationStatement");
    if (statement.length < 10) throw new Error("Bitte die Grundlage der Prüfberechtigung kurz beschreiben (z. B. «Eigene Website, Betreiberin: …»).");
    const v = validateUrl(baseUrl, loadPolicy());
    const extraHosts = lines(s(fd, "extraHosts")).map(normalizeHostname);
    if (extraHosts.some((h) => h.includes("*"))) throw new Error("Wildcard-Hosts sind nicht erlaubt. Jeder Host muss einzeln angegeben und verifiziert werden.");
    const scope = normalizeScope({ hosts: [v.hostname, ...extraHosts], includePaths: lines(s(fd, "includePaths")), excludePaths: lines(s(fd, "excludePaths")) });
    const apiSpecUrl = s(fd, "apiSpecUrl") || null;
    if (apiSpecUrl) validateUrl(apiSpecUrl, loadPolicy());
    const repoUrl = s(fd, "repoUrl") || null;
    if (repoUrl && !parseGithubUrl(repoUrl)) throw new Error("Repository bitte als https://github.com/<owner>/<repo> angeben.");
    const [site] = await db
      .insert(sites)
      .values({ orgId: org.id, name, baseUrl: v.url.origin + (v.url.pathname === "/" ? "/" : v.url.pathname), environment, ownerName, includePaths: scope.includePaths, excludePaths: scope.excludePaths, apiSpecUrl, repoUrl, authorizationConfirmedBy: user.userId, authorizationConfirmedAt: new Date(), authorizationStatement: statement })
      .returning();
    for (const host of scope.hosts) await db.insert(siteHosts).values({ siteId: site!.id, host, verificationToken: randomToken(24) }).onConflictDoNothing();
    const ip = await clientIp();
    await audit(db, { orgId: org.id, userId: user.userId, action: "site.created", targetType: "site", targetId: site!.id, details: { name, baseUrl, environment, hosts: scope.hosts }, ip });
    await audit(db, { orgId: org.id, userId: user.userId, action: "site.authorization_confirmed", targetType: "site", targetId: site!.id, details: { statement }, ip });
    siteId = site!.id;
  } catch (e) {
    fail("/sites/new", e instanceof NetguardError ? `URL abgelehnt: ${e.message}` : (e as Error).message);
  }
  redirect(`/sites/${siteId}?ok=${encodeURIComponent("Website angelegt. Bitte jetzt jeden Host technisch verifizieren.")}`);
}

export async function addHostAction(fd: FormData) {
  const user = await requireUser();
  const db = getDb();
  const siteId = s(fd, "siteId");
  try {
    const site = await requireSite(db, user.userId, siteId, "site.manage");
    const host = normalizeHostname(s(fd, "host"));
    if (host.includes("*")) throw new Error("Wildcards sind nicht erlaubt.");
    validateUrl(`https://${host}/`, loadPolicy());
    await db.insert(siteHosts).values({ siteId: site.id, host, verificationToken: randomToken(24) }).onConflictDoNothing();
    await audit(db, { orgId: site.orgId, userId: user.userId, action: "host.added", targetType: "site", targetId: site.id, details: { host }, ip: await clientIp() });
  } catch (e) {
    fail(`/sites/${siteId}`, (e as Error).message);
  }
  revalidatePath(`/sites/${siteId}`);
  redirect(`/sites/${siteId}?ok=${encodeURIComponent("Host hinzugefügt – Verifikation ausstehend.")}`);
}

export async function verifyHostAction(fd: FormData) {
  const user = await requireUser();
  const db = getDb();
  const siteId = s(fd, "siteId");
  const hostId = s(fd, "hostId");
  const method = s(fd, "method") as "dns_txt" | "file";
  let msg = "";
  let ok = false;
  try {
    const site = await requireSite(db, user.userId, siteId, "site.manage");
    const [h] = await db.select().from(siteHosts).where(and(eq(siteHosts.id, hostId), eq(siteHosts.siteId, site.id)));
    if (!h) throw new Error("Host nicht gefunden.");
    const base = new URL(site.baseUrl);
    const sameHost = normalizeHostname(base.hostname) === h.host;
    const res =
      method === "dns_txt"
        ? await verifyDnsTxt(h.host, h.verificationToken)
        : await verifyFile(h.host, h.verificationToken, {
            scheme: sameHost ? (base.protocol === "http:" ? "http" : "https") : "https",
            port: sameHost && base.port ? Number(base.port) : undefined,
            allowInvalidCerts: process.env.NODE_ENV !== "production" && process.env.WEBAUDIT_ALLOW_INVALID_CERTS === "true",
          });
    await db.update(siteHosts).set({ lastCheckAt: new Date(), lastCheckResult: res.detail, ...(res.ok ? { verifiedAt: new Date(), verificationMethod: res.method } : {}) }).where(eq(siteHosts.id, h.id));
    await audit(db, { orgId: site.orgId, userId: user.userId, action: res.ok ? "host.verified" : "host.verification_failed", targetType: "site_host", targetId: h.id, details: { host: h.host, method, detail: res.detail }, ip: await clientIp() });
    ok = res.ok;
    msg = res.detail;
  } catch (e) {
    msg = (e as Error).message;
  }
  revalidatePath(`/sites/${siteId}`);
  redirect(`/sites/${siteId}?${ok ? "ok" : "error"}=${encodeURIComponent(msg)}`);
}

export async function addCredentialAction(fd: FormData) {
  const user = await requireUser();
  const db = getDb();
  const siteId = s(fd, "siteId");
  try {
    const site = await requireSite(db, user.userId, siteId, "credential.manage");
    const kind = s(fd, "kind") as "header" | "cookie" | "github_token";
    if (!["header", "cookie", "github_token"].includes(kind)) throw new Error("Ungültige Art.");
    const label = s(fd, "label");
    const value = String(fd.get("value") ?? "");
    if (!label || !value) throw new Error("Bezeichnung und Wert sind Pflichtfelder.");
    if (value.length > 8192 || /[\r\n]/.test(value)) throw new Error("Der Wert darf keine Zeilenumbrüche enthalten und höchstens 8192 Zeichen lang sein.");
    const headerName = kind === "header" ? s(fd, "headerName") || "Authorization" : null;
    if (headerName && !/^[A-Za-z0-9-]{1,64}$/.test(headerName)) throw new Error("Ungültiger Header-Name.");
    const verifyUrl = s(fd, "verifyUrl") || null;
    const logoutUrl = s(fd, "logoutUrl") || null;
    for (const u of [verifyUrl, logoutUrl]) if (u) validateUrl(u, loadPolicy());
    const [c] = await db.insert(credentials).values({ siteId: site.id, label, kind, headerName, encryptedValue: encryptSecret(value), verifyUrl, logoutUrl, createdBy: user.userId }).returning();
    await audit(db, { orgId: site.orgId, userId: user.userId, action: "credential.created", targetType: "credential", targetId: c!.id, details: { label, kind, headerName }, ip: await clientIp() });
  } catch (e) {
    fail(`/sites/${siteId}`, (e as Error).message);
  }
  revalidatePath(`/sites/${siteId}`);
  redirect(`/sites/${siteId}?ok=${encodeURIComponent("Zugang verschlüsselt gespeichert.")}`);
}

export async function deleteCredentialAction(fd: FormData) {
  const user = await requireUser();
  const db = getDb();
  const siteId = s(fd, "siteId");
  const site = await requireSite(db, user.userId, siteId, "credential.manage");
  const id = s(fd, "credentialId");
  await db.delete(credentials).where(and(eq(credentials.id, id), eq(credentials.siteId, site.id)));
  await audit(db, { orgId: site.orgId, userId: user.userId, action: "credential.deleted", targetType: "credential", targetId: id, ip: await clientIp() });
  revalidatePath(`/sites/${siteId}`);
  redirect(`/sites/${siteId}?ok=${encodeURIComponent("Zugang gelöscht.")}`);
}

export async function createApprovalAction(fd: FormData) {
  const user = await requireUser();
  const db = getDb();
  const siteId = s(fd, "siteId");
  try {
    const site = await requireSite(db, user.userId, siteId, "approval.manage");
    if (fd.get("confirmActive") !== "on") throw new Error("Die ausdrückliche Bestätigung für aktive Prüfungen fehlt.");
    const windowStart = new Date(s(fd, "windowStart"));
    const windowEnd = new Date(s(fd, "windowEnd"));
    if (!(windowStart.getTime() > 0) || !(windowEnd.getTime() > windowStart.getTime())) throw new Error("Ungültiges Zeitfenster.");
    if (windowEnd.getTime() - windowStart.getTime() > 7 * 24 * 3600_000) throw new Error("Das Zeitfenster darf höchstens 7 Tage betragen.");
    const maxRequests = Math.min(5000, Math.max(10, Number(s(fd, "maxRequests")) || 1000));
    const rps = Math.min(10, Math.max(1, Number(s(fd, "requestsPerSecond")) || 2));
    const allowWriteEffects = fd.get("allowWriteEffects") === "on";
    if (allowWriteEffects && site.environment === "production") throw new Error("Prüfungen mit möglichen Schreibwirkungen sind auf Produktion nicht zulässig.");
    const statement = s(fd, "statement");
    if (statement.length < 10) throw new Error("Bitte Zweck und Rahmen der aktiven Prüfung beschreiben.");
    const [ap] = await db
      .insert(scanApprovals)
      .values({ siteId: site.id, mode: "active", profile: "webaudit-safe", targetUrl: site.baseUrl, scopeSummary: `Hosts: verifizierte Hosts; Pfade: ${site.includePaths.join(", ")}; Ausschlüsse: ${site.excludePaths.join(", ") || "–"}`, windowStart, windowEnd, maxRequests, requestsPerSecond: rps, allowWriteEffects, approvedBy: user.userId, statement })
      .returning();
    await audit(db, { orgId: site.orgId, userId: user.userId, action: "approval.created", targetType: "approval", targetId: ap!.id, details: { windowStart, windowEnd, maxRequests, rps, allowWriteEffects, statement }, ip: await clientIp() });
  } catch (e) {
    fail(`/sites/${siteId}`, (e as Error).message);
  }
  revalidatePath(`/sites/${siteId}`);
  redirect(`/sites/${siteId}?ok=${encodeURIComponent("Freigabe für aktive Prüfung erfasst.")}`);
}

export async function revokeApprovalAction(fd: FormData) {
  const user = await requireUser();
  const db = getDb();
  const siteId = s(fd, "siteId");
  const site = await requireSite(db, user.userId, siteId, "approval.manage");
  const id = s(fd, "approvalId");
  await db.update(scanApprovals).set({ revokedAt: new Date() }).where(and(eq(scanApprovals.id, id), eq(scanApprovals.siteId, site.id)));
  await audit(db, { orgId: site.orgId, userId: user.userId, action: "approval.revoked", targetType: "approval", targetId: id, ip: await clientIp() });
  revalidatePath(`/sites/${siteId}`);
  redirect(`/sites/${siteId}?ok=${encodeURIComponent("Freigabe widerrufen.")}`);
}
