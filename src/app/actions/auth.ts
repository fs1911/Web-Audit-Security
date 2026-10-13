"use server";

import { cookies } from "next/headers";
import { redirect } from "next/navigation";
import { getDb } from "@/lib/db";
import { authenticate, createSession, deleteSession, registerUser, registrationAllowed, SESSION_COOKIE } from "@/lib/auth/session";
import { clientIp } from "@/lib/auth/current";
import { audit } from "@/lib/audit";

async function setSessionCookie(token: string, expiresAt: Date) {
  const jar = await cookies();
  jar.set(SESSION_COOKIE, token, { httpOnly: true, secure: process.env.NODE_ENV === "production", sameSite: "lax", path: "/", expires: expiresAt });
}

export async function registerAction(formData: FormData) {
  const db = getDb();
  if (!(await registrationAllowed(db))) redirect("/register?error=" + encodeURIComponent("Die Registrierung ist auf dieser Installation geschlossen."));
  let target = "/";
  try {
    const { user } = await registerUser(db, {
      email: String(formData.get("email") ?? ""),
      name: String(formData.get("name") ?? ""),
      password: String(formData.get("password") ?? ""),
      orgName: String(formData.get("orgName") ?? ""),
    });
    const s = await createSession(db, user.id);
    await setSessionCookie(s.token, s.expiresAt);
  } catch (e) {
    target = "/register?error=" + encodeURIComponent((e as Error).message);
  }
  redirect(target);
}

export async function loginAction(formData: FormData) {
  const db = getDb();
  let target = "/";
  try {
    const user = await authenticate(db, String(formData.get("email") ?? ""), String(formData.get("password") ?? ""), await clientIp());
    const s = await createSession(db, user.id);
    await setSessionCookie(s.token, s.expiresAt);
  } catch (e) {
    target = "/login?error=" + encodeURIComponent((e as Error).message);
  }
  redirect(target);
}

export async function logoutAction() {
  const jar = await cookies();
  const token = jar.get(SESSION_COOKIE)?.value;
  if (token) {
    await deleteSession(getDb(), token);
    await audit(getDb(), { action: "user.logout" });
  }
  jar.delete(SESSION_COOKIE);
  redirect("/login");
}
