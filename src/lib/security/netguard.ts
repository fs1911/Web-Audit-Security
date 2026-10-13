import dns from "node:dns";
import net from "node:net";
import { classifyIp, parseCidrList, type Cidr } from "./ip";

/**
 * Netzwerkschutz für alle ausgehenden Verbindungen der Plattform (native Checks,
 * Domainverifikation, Egress-Proxy für ZAP und Unterprozesse).
 *
 * Garantien:
 * - Nur http/https, keine eingebetteten Zugangsdaten, nur erlaubte Ports.
 * - Hostnamen werden mit dem WHATWG-URL-Parser normalisiert. Dadurch werden alternative
 *   IP-Schreibweisen (dezimal, oktal, hexadezimal, gekürzt) in die kanonische Form überführt,
 *   bevor geprüft wird.
 * - Die DNS-Auflösung erfolgt bei JEDEM Verbindungsaufbau (über `guardedLookup`) und die
 *   Verbindung wird auf genau die geprüfte IP aufgebaut. Damit bleibt kein Zeitfenster für
 *   DNS-Rebinding zwischen Prüfung und Verbindung.
 */

export class NetguardError extends Error {
  constructor(
    message: string,
    public readonly code:
      | "INVALID_URL"
      | "SCHEME"
      | "CREDENTIALS"
      | "PORT"
      | "HOSTNAME"
      | "BLOCKED_IP"
      | "DNS"
      | "OUT_OF_SCOPE"
      | "BUDGET",
  ) {
    super(message);
    this.name = "NetguardError";
  }
}

export type NetguardPolicy = {
  allowedPorts: Set<number>;
  /** Nur ausserhalb von production wirksam (z. B. für lokale Testziele). */
  testAllowCidrs: Cidr[];
};

export function isProduction(): boolean {
  return process.env.NODE_ENV === "production" || process.env.WEBAUDIT_ENV === "production";
}

export function loadPolicy(env: NodeJS.ProcessEnv = process.env): NetguardPolicy {
  const prod = env.NODE_ENV === "production" || env.WEBAUDIT_ENV === "production";
  const ports = new Set<number>([80, 443]);
  let testAllowCidrs: Cidr[] = [];
  if (!prod) {
    testAllowCidrs = parseCidrList(env.NETGUARD_TEST_ALLOW_CIDRS);
    for (const p of (env.NETGUARD_TEST_ALLOW_PORTS ?? "").split(",").map((s) => Number(s.trim()))) {
      if (Number.isInteger(p) && p > 0 && p < 65536) ports.add(p);
    }
  }
  return { allowedPorts: ports, testAllowCidrs };
}

const BLOCKED_HOSTNAMES = new Set(["localhost", "localhost.localdomain", "ip6-localhost", "ip6-loopback", "metadata.google.internal", "metadata"]);
const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".intranet", ".lan", ".home.arpa", ".corp", ".svc.cluster.local"];

export function normalizeHostname(hostname: string): string {
  let h = hostname.toLowerCase();
  if (h.startsWith("[") && h.endsWith("]")) h = h.slice(1, -1);
  if (h.endsWith(".")) h = h.slice(0, -1);
  return h;
}

export type ValidatedUrl = { url: URL; hostname: string; port: number; isIpLiteral: boolean };

/** Statische Prüfung einer URL (ohne DNS). */
export function validateUrl(input: string, policy: NetguardPolicy = loadPolicy()): ValidatedUrl {
  if (typeof input !== "string" || input.length > 2048) throw new NetguardError("URL fehlt oder ist zu lang", "INVALID_URL");
  if (/[\u0000-\u001f\s\\]/.test(input)) throw new NetguardError("URL enthält unzulässige Zeichen", "INVALID_URL");
  let url: URL;
  try {
    url = new URL(input);
  } catch {
    throw new NetguardError("URL ist ungültig", "INVALID_URL");
  }
  if (url.protocol !== "http:" && url.protocol !== "https:") {
    throw new NetguardError("Nur http:// und https:// sind erlaubt", "SCHEME");
  }
  if (url.username || url.password) {
    throw new NetguardError("URLs mit eingebetteten Zugangsdaten werden abgelehnt", "CREDENTIALS");
  }
  const port = url.port ? Number(url.port) : url.protocol === "https:" ? 443 : 80;
  if (!policy.allowedPorts.has(port)) throw new NetguardError(`Port ${port} ist nicht freigegeben`, "PORT");
  const hostname = normalizeHostname(url.hostname);
  if (!hostname) throw new NetguardError("Hostname fehlt", "HOSTNAME");
  const isIpLiteral = net.isIP(hostname) !== 0;
  if (isIpLiteral) {
    const verdict = classifyIp(hostname, policy.testAllowCidrs);
    if (!verdict.allowed) throw new NetguardError(`Ziel blockiert: ${verdict.reason}`, "BLOCKED_IP");
  } else {
    if (BLOCKED_HOSTNAMES.has(hostname) || BLOCKED_SUFFIXES.some((s) => hostname.endsWith(s))) {
      throw new NetguardError(`Interner Hostname blockiert: ${hostname}`, "HOSTNAME");
    }
    if (!hostname.includes(".")) throw new NetguardError("Hostname ohne Domain wird abgelehnt", "HOSTNAME");
    if (!/^[a-z0-9.-]+$/.test(hostname)) throw new NetguardError("Hostname enthält unzulässige Zeichen", "HOSTNAME");
  }
  return { url, hostname, port, isIpLiteral };
}

export type Resolver = (hostname: string) => Promise<{ address: string; family: number }[]>;

export const systemResolver: Resolver = async (hostname) => dns.promises.lookup(hostname, { all: true, verbatim: true });

/**
 * Löst einen Hostnamen auf und gibt die erste erlaubte Adresse zurück.
 * Ist IRGENDEINE der aufgelösten Adressen blockiert, wird abgelehnt (verhindert
 * Mischantworten, bei denen der Client eine interne Adresse wählen könnte).
 */
export async function resolveSafe(
  hostname: string,
  policy: NetguardPolicy = loadPolicy(),
  resolver: Resolver = systemResolver,
): Promise<{ address: string; family: 4 | 6 }> {
  const h = normalizeHostname(hostname);
  if (net.isIP(h)) {
    const v = classifyIp(h, policy.testAllowCidrs);
    if (!v.allowed) throw new NetguardError(`Ziel blockiert: ${v.reason}`, "BLOCKED_IP");
    return { address: h, family: v.family };
  }
  let records: { address: string; family: number }[];
  try {
    records = await resolver(h);
  } catch (e) {
    throw new NetguardError(`DNS-Auflösung fehlgeschlagen für ${h}`, "DNS");
  }
  if (records.length === 0) throw new NetguardError(`Keine DNS-Antwort für ${h}`, "DNS");
  for (const r of records) {
    const v = classifyIp(r.address, policy.testAllowCidrs);
    if (!v.allowed) throw new NetguardError(`${h} löst auf blockierte Adresse auf (${v.reason})`, "BLOCKED_IP");
  }
  const first = records[0]!;
  return { address: first.address, family: first.family === 6 ? 6 : 4 };
}

/**
 * `lookup`-Funktion für node:http/https/net/tls. Wird bei jedem Socket-Aufbau aufgerufen.
 */
export function guardedLookup(policy: NetguardPolicy = loadPolicy(), resolver: Resolver = systemResolver) {
  return (
    hostname: string,
    options: dns.LookupOptions | number | undefined,
    callback: (err: NodeJS.ErrnoException | null, address: string | dns.LookupAddress[], family?: number) => void,
  ) => {
    resolveSafe(hostname, policy, resolver).then(
      ({ address, family }) => {
        const wantAll = typeof options === "object" && options !== null && options.all;
        if (wantAll) callback(null, [{ address, family }]);
        else callback(null, address, family);
      },
      (err: Error) => callback(Object.assign(err, { code: "ENETGUARD" }) as NodeJS.ErrnoException, "", 0),
    );
  };
}
