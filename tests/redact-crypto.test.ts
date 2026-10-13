import { describe, expect, it } from "vitest";
import { redact, redactDeep } from "../src/lib/security/redact";
import { decryptSecret, encryptSecret, jobToken, signBody, verifyJobSignature } from "../src/lib/security/crypto";

describe("Geheimnisbereinigung", () => {
  it("entfernt Authorization- und Cookie-Werte, behält Cookie-Attribute", () => {
    const out = redact("Authorization: Bearer abc.def.ghi\nCookie: sid=123; theme=dark\nSet-Cookie: sessionid=XYZ; Path=/; HttpOnly");
    expect(out).not.toContain("abc.def.ghi");
    expect(out).not.toContain("123");
    expect(out).not.toContain("XYZ");
    expect(out).toContain("Bearer [ENTFERNT]");
    expect(out).toContain("sessionid=[ENTFERNT]; Path=/; HttpOnly");
  });
  it("entfernt bekannte Token-Formate", () => {
    const s = "key AKIAABCDEFGHIJKLMNOP gh ghp_abcdefghijklmnopqrstuvwxyz0123456789 ant sk-ant-api03-abcdefghijklmnopqrstuv jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0In0.c2lnbmF0dXJlMTIz";
    const out = redact(s);
    for (const secret of ["AKIAABCDEFGHIJKLMNOP", "ghp_abcdefghijklmnopqrstuvwxyz0123456789", "sk-ant-api03-abcdefghijklmnopqrstuv", "eyJhbGciOiJIUzI1NiJ9"]) expect(out).not.toContain(secret);
  });
  it("entfernt Zugangsdaten in URLs und Parametern", () => {
    const out = redact("https://admin:hunter2@example.ch/x?token=abc123&page=2 password=geheim");
    expect(out).not.toContain("hunter2");
    expect(out).not.toContain("abc123");
    expect(out).not.toContain("geheim");
    expect(out).toContain("page=2");
  });
  it("entfernt explizit bekannte Secrets (z. B. hinterlegte Testzugänge) überall", () => {
    const out = redact("Antwort enthielt tt-session-SuperGeheim-4711 im Text", { knownSecrets: ["tt-session-SuperGeheim-4711"] });
    expect(out).not.toContain("SuperGeheim");
  });
  it("entfernt E-Mail-Adressen und kürzt lange Inhalte", () => {
    const out = redact("Kontakt: max.muster@example.ch " + "x".repeat(5000), { maxLength: 100 });
    expect(out).not.toContain("max.muster@example.ch");
    expect(out).toMatch(/gekürzt/);
  });
  it("bereinigt verschachtelte Strukturen", () => {
    const out = redactDeep({ a: { password: "p", token: "t", list: ["Authorization: Bearer zzz"] } });
    expect(JSON.stringify(out)).not.toMatch(/"p"|"t"|zzz/);
  });
});

describe("Verschlüsselung und Signaturen", () => {
  it("verschlüsselt authentifiziert (AES-256-GCM)", () => {
    const c = encryptSecret("Bearer geheim");
    expect(c).not.toContain("geheim");
    expect(decryptSecret(c)).toBe("Bearer geheim");
    const tampered = c.slice(0, -4) + (c.endsWith("A") ? "B" : "A") + c.slice(-3);
    expect(() => decryptSecret(tampered)).toThrow();
  });
  it("prüft job-spezifische Callback-Signaturen inkl. Zeitfenster", () => {
    const jobId = "11111111-1111-4111-8111-111111111111";
    const body = JSON.stringify({ type: "heartbeat" });
    const ts = String(Date.now());
    const sig = signBody(jobToken(jobId), ts, body);
    expect(verifyJobSignature(jobId, ts, body, sig)).toBe(true);
    expect(verifyJobSignature("22222222-2222-4222-8222-222222222222", ts, body, sig)).toBe(false);
    expect(verifyJobSignature(jobId, ts, body + " ", sig)).toBe(false);
    const old = String(Date.now() - 10 * 60_000);
    expect(verifyJobSignature(jobId, old, body, signBody(jobToken(jobId), old, body))).toBe(false);
  });
});
