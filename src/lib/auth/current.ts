import "server-only";
import { cookies, headers } from "next/headers";
import { redirect } from "next/navigation";
import { getDb } from "../db";
import { SESSION_COOKIE, userOrgs, validateSessionToken } from "./session";

export async function currentUser() {
  const jar = await cookies();
  return validateSessionToken(getDb(), jar.get(SESSION_COOKIE)?.value);
}

export async function requireUser() {
  const u = await currentUser();
  if (!u) redirect("/login");
  return u;
}

/** Aktive Organisation: erste Mitgliedschaft (Mehrfach-Organisationen über Cookie wählbar). */
export async function requireUserAndOrg() {
  const user = await requireUser();
  const orgs = await userOrgs(getDb(), user.userId);
  const jar = await cookies();
  const wanted = jar.get("wa_org")?.value;
  const org = orgs.find((o) => o.id === wanted) ?? orgs[0];
  if (!org) redirect("/login");
  return { user, org, orgs };
}

export async function clientIp(): Promise<string | null> {
  const h = await headers();
  return h.get("x-forwarded-for")?.split(",")[0]?.trim() ?? h.get("x-real-ip") ?? null;
}

/** CSRF-Schutz für Route-Handler: Origin muss mit Host übereinstimmen. */
export async function assertSameOrigin() {
  const h = await headers();
  const origin = h.get("origin");
  const host = h.get("x-forwarded-host") ?? h.get("host");
  if (!origin || !host) throw new Error("Anfrage ohne Origin abgelehnt");
  if (new URL(origin).host !== host) throw new Error("Cross-Origin-Anfrage abgelehnt");
}
