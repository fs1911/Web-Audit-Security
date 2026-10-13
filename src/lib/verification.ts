import dns from "node:dns";
import { guardedRequest } from "./security/http";
import { loadPolicy, normalizeHostname, validateUrl, type NetguardPolicy, type Resolver } from "./security/netguard";

/**
 * Technische Domainverifikation. Jeder Host wird einzeln verifiziert – eine verifizierte
 * Domain gibt KEINE Subdomains frei.
 *
 * DNS-TXT:  _webaudit-verification.<host>  TXT  "webaudit-verification=<token>"
 * Datei:    http(s)://<host>/.well-known/webaudit-verification.txt  enthält  <token>
 *           (Weiterleitungen werden nur innerhalb desselben Hosts akzeptiert)
 */

export const TXT_PREFIX = "_webaudit-verification";
export const FILE_PATH = "/.well-known/webaudit-verification.txt";

export type VerificationResult = { ok: boolean; method: "dns_txt" | "file"; detail: string };

export type TxtResolver = (name: string) => Promise<string[][]>;

export async function verifyDnsTxt(host: string, token: string, resolveTxt: TxtResolver = dns.promises.resolveTxt): Promise<VerificationResult> {
  const name = `${TXT_PREFIX}.${normalizeHostname(host)}`;
  try {
    const records = await resolveTxt(name);
    const flat = records.map((chunks) => chunks.join(""));
    const ok = flat.some((r) => r.trim() === `webaudit-verification=${token}`);
    return { ok, method: "dns_txt", detail: ok ? `TXT-Eintrag auf ${name} gefunden` : `Kein passender TXT-Eintrag auf ${name} (gefunden: ${flat.length})` };
  } catch (e) {
    return { ok: false, method: "dns_txt", detail: `DNS-Abfrage für ${name} fehlgeschlagen (${(e as NodeJS.ErrnoException).code ?? "Fehler"})` };
  }
}

export async function verifyFile(
  host: string,
  token: string,
  opts: { scheme?: "https" | "http"; port?: number; policy?: NetguardPolicy; resolver?: Resolver; allowInvalidCerts?: boolean } = {},
): Promise<VerificationResult> {
  const h = normalizeHostname(host);
  const scheme = opts.scheme ?? "https";
  const portPart = opts.port && opts.port !== (scheme === "https" ? 443 : 80) ? `:${opts.port}` : "";
  const url = `${scheme}://${h.includes(":") ? `[${h}]` : h}${portPart}${FILE_PATH}`;
  const policy = opts.policy ?? loadPolicy();
  try {
    validateUrl(url, policy);
    const res = await guardedRequest(url, {
      policy,
      resolver: opts.resolver,
      // Weiterleitungen nur auf denselben Host
      scope: { hosts: [h], includePaths: ["/"], excludePaths: [] },
      maxBodyBytes: 4096,
      timeoutMs: 10000,
      allowInvalidCerts: opts.allowInvalidCerts,
    });
    if (res.blockedRedirect) return { ok: false, method: "file", detail: `Weiterleitung auf anderes Ziel abgelehnt: ${res.blockedRedirect.reason}` };
    if (res.status !== 200) return { ok: false, method: "file", detail: `${url} antwortete mit Status ${res.status}` };
    const ok = res.body.split(/\r?\n/).some((line) => line.trim() === token);
    return { ok, method: "file", detail: ok ? `Token in ${url} gefunden` : `Token in ${url} nicht gefunden` };
  } catch (e) {
    return { ok: false, method: "file", detail: `Abruf von ${url} fehlgeschlagen: ${(e as Error).message}` };
  }
}
