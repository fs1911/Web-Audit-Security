import crypto from "node:crypto";

/**
 * Verschlüsselung von Zugangsdaten (AES-256-GCM) und Signaturen für Worker-Callbacks.
 * Der Schlüssel kommt aus APP_ENCRYPTION_KEY (32 Byte, base64). Ohne Schlüssel
 * verweigert die Anwendung das Speichern von Zugangsdaten.
 */

function key(): Buffer {
  const raw = process.env.APP_ENCRYPTION_KEY;
  if (!raw) throw new Error("APP_ENCRYPTION_KEY ist nicht gesetzt – Zugangsdaten können nicht verschlüsselt werden.");
  const k = Buffer.from(raw, "base64");
  if (k.length !== 32) throw new Error("APP_ENCRYPTION_KEY muss 32 Byte (base64) lang sein.");
  return k;
}

export function encryptSecret(plaintext: string, aad = "webaudit:v1"): string {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv("aes-256-gcm", key(), iv);
  cipher.setAAD(Buffer.from(aad));
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
  const tag = cipher.getAuthTag();
  return ["v1", iv.toString("base64"), tag.toString("base64"), ct.toString("base64")].join(".");
}

export function decryptSecret(payload: string, aad = "webaudit:v1"): string {
  const [v, ivB, tagB, ctB] = payload.split(".");
  if (v !== "v1" || !ivB || !tagB || !ctB) throw new Error("Unbekanntes Verschlüsselungsformat");
  const decipher = crypto.createDecipheriv("aes-256-gcm", key(), Buffer.from(ivB, "base64"));
  decipher.setAAD(Buffer.from(aad));
  decipher.setAuthTag(Buffer.from(tagB, "base64"));
  return Buffer.concat([decipher.update(Buffer.from(ctB, "base64")), decipher.final()]).toString("utf8");
}

export function randomToken(bytes = 32): string {
  return crypto.randomBytes(bytes).toString("base64url");
}

export function sha256(data: string | Buffer): string {
  return crypto.createHash("sha256").update(data).digest("hex");
}

function callbackSecret(): string {
  const s = process.env.RUNNER_CALLBACK_SECRET;
  if (!s || s.length < 32) throw new Error("RUNNER_CALLBACK_SECRET fehlt oder ist zu kurz (mind. 32 Zeichen).");
  return s;
}

/** Job-spezifisches Token: Der Runner erhält nur dieses, nie das globale Secret. */
export function jobToken(jobId: string): string {
  return crypto.createHmac("sha256", callbackSecret()).update(`job:${jobId}`).digest("base64url");
}

export function signBody(token: string, timestamp: string, body: string): string {
  return crypto.createHmac("sha256", token).update(`${timestamp}.${body}`).digest("hex");
}

export function verifyJobSignature(jobId: string, timestamp: string, body: string, signature: string, maxSkewMs = 5 * 60_000): boolean {
  const ts = Number(timestamp);
  if (!Number.isFinite(ts) || Math.abs(Date.now() - ts) > maxSkewMs) return false;
  const expected = signBody(jobToken(jobId), timestamp, body);
  const a = Buffer.from(expected, "hex");
  const b = Buffer.from(signature, "hex");
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

export function safeEqual(a: string, b: string): boolean {
  const ab = Buffer.from(a);
  const bb = Buffer.from(b);
  return ab.length === bb.length && crypto.timingSafeEqual(ab, bb);
}
