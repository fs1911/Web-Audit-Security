/**
 * Zentrale Bereinigung (Redaction) für Logs, Nachweise, Reports und KI-Payloads.
 *
 * Grundsatz: Lieber zu viel als zu wenig entfernen. Nachweise sollen belegen, DASS
 * etwas vorhanden ist, nicht den Wert selbst offenlegen.
 */

const REDACTED = "[ENTFERNT]";

const SENSITIVE_HEADER_NAMES = ["authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "x-csrf-token", "x-xsrf-token"];

const PATTERNS: { re: RegExp; replace: string | ((m: string, ...g: string[]) => string) }[] = [
  // Header-Zeilen mit sensiblen Werten
  {
    re: new RegExp(`^((?:${SENSITIVE_HEADER_NAMES.join("|")})\\s*:\\s*)(.+)$`, "gim"),
    replace: (_m, p1: string, p2: string) => {
      // Bei Set-Cookie: Name + Attribute behalten, Wert entfernen (Attribute sind Prüfgegenstand)
      if (/^set-cookie/i.test(p1)) return p1 + redactCookieValue(p2);
      if (/^cookie/i.test(p1)) return p1 + p2.split(";").map((c) => redactCookieValue(c.trim())).join("; ");
      const scheme = p2.match(/^(Bearer|Basic|Digest|Token)\s+/i);
      return p1 + (scheme ? scheme[0] : "") + REDACTED;
    },
  },
  // Bearer/Basic-Token auch ausserhalb von Header-Zeilen
  { re: /\b(Bearer|Basic)\s+(?!\[ENTFERNT\])[A-Za-z0-9._~+\/=-]{6,}/g, replace: (_m, scheme: string) => `${scheme} ${REDACTED}` },
  // Bekannte Secret-Formate
  { re: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/g, replace: REDACTED + "(AWS-Key)" },
  { re: /\bgh[pousr]_[A-Za-z0-9]{30,}\b/g, replace: REDACTED + "(GitHub-Token)" },
  { re: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g, replace: REDACTED + "(GitHub-Token)" },
  { re: /\bsk-ant-[A-Za-z0-9_-]{20,}\b/g, replace: REDACTED + "(Anthropic-Key)" },
  { re: /\bsk-[A-Za-z0-9]{20,}\b/g, replace: REDACTED + "(API-Key)" },
  { re: /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g, replace: REDACTED + "(Slack-Token)" },
  { re: /\bAIza[0-9A-Za-z_-]{35}\b/g, replace: REDACTED + "(Google-Key)" },
  { re: /-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----/g, replace: REDACTED + "(Private Key)" },
  { re: /\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b/g, replace: REDACTED + "(JWT)" },
  // Zugangsdaten in URLs
  { re: /([a-z][a-z0-9+.-]*:\/\/)([^\s/:@]+):([^\s/@]+)@/gi, replace: (_m, s: string) => `${s}${REDACTED}@` },
  // Query-/Formularparameter mit sensiblen Namen
  {
    re: /([?&;\s"']|^)((?:pass(?:word|wd)?|pwd|secret|token|api[_-]?key|access[_-]?token|refresh[_-]?token|session(?:id)?|sid|auth|client[_-]?secret|code)=)([^&\s"';]+)/gim,
    replace: (_m, pre: string, key: string) => `${pre}${key}${REDACTED}`,
  },
  // JSON-Felder mit sensiblen Namen
  {
    re: /("(?:password|passwd|secret|token|apiKey|api_key|accessToken|access_token|refreshToken|refresh_token|clientSecret|client_secret|authorization)"\s*:\s*)"[^"]*"/gi,
    replace: (_m, p1: string) => `${p1}"${REDACTED}"`,
  },
  // Personenbezogene Daten in Antwortausschnitten
  { re: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g, replace: "[E-MAIL ENTFERNT]" },
  { re: /(?<![\w.])\+?\d{2,3}[\s/-]?\(?\d{2,3}\)?[\s/-]?\d{3}[\s/-]?\d{2}[\s/-]?\d{2}(?![\w.])/g, replace: "[TELEFON ENTFERNT]" },
  { re: /\bCH\d{2}\s?(?:[0-9A-Z]{4}\s?){4}[0-9A-Z]{1}\b/g, replace: "[IBAN ENTFERNT]" },
];

function redactCookieValue(cookie: string): string {
  const eq = cookie.indexOf("=");
  if (eq < 0) return cookie;
  const name = cookie.slice(0, eq);
  const rest = cookie.slice(eq + 1);
  const semi = rest.indexOf(";");
  return `${name}=${REDACTED}${semi >= 0 ? rest.slice(semi) : ""}`;
}

export type RedactOptions = { maxLength?: number; knownSecrets?: string[] };

export function redact(input: string | null | undefined, opts: RedactOptions = {}): string {
  if (!input) return "";
  let out = String(input);
  // Explizit bekannte Secrets (z. B. hinterlegte Testpasswörter) immer zuerst entfernen
  for (const s of opts.knownSecrets ?? []) {
    if (s && s.length >= 4) out = out.split(s).join(REDACTED);
  }
  for (const p of PATTERNS) {
    out = out.replace(p.re, p.replace as never);
  }
  const max = opts.maxLength ?? 2000;
  if (out.length > max) out = out.slice(0, max) + ` … [gekürzt, ${out.length - max} Zeichen]`;
  return out;
}

/** Tiefe Bereinigung beliebiger JSON-Strukturen. */
export function redactDeep<T>(value: T, opts: RedactOptions = {}): T {
  if (typeof value === "string") return redact(value, { maxLength: 10000, ...opts }) as T;
  if (Array.isArray(value)) return value.map((v) => redactDeep(v, opts)) as T;
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [k, v] of Object.entries(value as Record<string, unknown>)) {
      if (/^(password|passwd|secret|token|apiKey|api_key|authorization|cookie|clientSecret|accessToken|refreshToken|encrypted.*)$/i.test(k)) {
        out[k] = v == null ? v : REDACTED;
      } else out[k] = redactDeep(v, opts);
    }
    return out as T;
  }
  return value;
}

export { REDACTED };
