import { argon2idAsync } from "@noble/hashes/argon2.js";
import crypto from "node:crypto";

// OWASP Password Storage Cheat Sheet: argon2id, m=19 MiB, t=2, p=1
const PARAMS = { t: 2, m: 19456, p: 1, dkLen: 32 } as const;

export async function hashPassword(password: string): Promise<string> {
  const salt = crypto.randomBytes(16);
  const hash = await argon2idAsync(password, salt, PARAMS);
  return `argon2id$v=19$m=${PARAMS.m},t=${PARAMS.t},p=${PARAMS.p}$${salt.toString("base64")}$${Buffer.from(hash).toString("base64")}`;
}

export async function verifyPassword(password: string, stored: string): Promise<boolean> {
  const parts = stored.split("$");
  if (parts.length !== 5 || parts[0] !== "argon2id") return false;
  const params = Object.fromEntries(parts[2]!.split(",").map((kv) => kv.split("=")).map(([k, v]) => [k, Number(v)]));
  const salt = Buffer.from(parts[3]!, "base64");
  const expected = Buffer.from(parts[4]!, "base64");
  const actual = Buffer.from(await argon2idAsync(password, salt, { t: params.t!, m: params.m!, p: params.p!, dkLen: expected.length }));
  return actual.length === expected.length && crypto.timingSafeEqual(actual, expected);
}

export function validatePasswordStrength(pw: string): string | null {
  if (pw.length < 12) return "Das Passwort muss mindestens 12 Zeichen lang sein.";
  if (pw.length > 256) return "Das Passwort ist zu lang.";
  return null;
}
