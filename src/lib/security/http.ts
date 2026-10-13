import http from "node:http";
import https from "node:https";
import tls from "node:tls";
import { guardedLookup, loadPolicy, NetguardError, validateUrl, type NetguardPolicy, type Resolver, systemResolver } from "./netguard";
import { checkScope, type Scope } from "./scope";

export type GuardedResponse = {
  url: string;
  status: number;
  headers: Record<string, string | string[]>;
  body: string;
  truncated: boolean;
  remoteAddress?: string;
  redirectChain: { url: string; status: number; location?: string }[];
  blockedRedirect?: { location: string; reason: string };
};

export type GuardedRequestOptions = {
  method?: "GET" | "HEAD";
  headers?: Record<string, string>;
  maxRedirects?: number;
  timeoutMs?: number;
  maxBodyBytes?: number;
  /** Wenn gesetzt, müssen alle Ziele (inkl. Redirects) im Scope liegen. */
  scope?: Scope;
  policy?: NetguardPolicy;
  resolver?: Resolver;
  /** Für Testziele mit selbstsignierten Zertifikaten (nur ausserhalb production). */
  allowInvalidCerts?: boolean;
  onRequest?: (url: string) => void;
};

/**
 * HTTP-Client mit Netzwerkschutz. Ausschliesslich GET/HEAD — es werden niemals
 * Formulare abgesendet. Redirects werden manuell verfolgt und pro Hop gegen Scope
 * und Netguard geprüft.
 */
export async function guardedRequest(rawUrl: string, opts: GuardedRequestOptions = {}): Promise<GuardedResponse> {
  const policy = opts.policy ?? loadPolicy();
  const resolver = opts.resolver ?? systemResolver;
  const maxRedirects = opts.maxRedirects ?? 5;
  const chain: GuardedResponse["redirectChain"] = [];
  let current = rawUrl;
  for (let hop = 0; hop <= maxRedirects; hop++) {
    if (opts.scope) {
      const d = checkScope(current, opts.scope, policy, { stateChangingGuard: false });
      if (!d.inScope) {
        if (hop === 0) throw new NetguardError(d.reason, "OUT_OF_SCOPE");
        const prev = chain[chain.length - 1]!;
        return { ...emptyResp(prev.url, prev.status), redirectChain: chain, blockedRedirect: { location: current, reason: d.reason } };
      }
    } else {
      try {
        validateUrl(current, policy);
      } catch (e) {
        if (hop === 0) throw e;
        const prev = chain[chain.length - 1]!;
        return { ...emptyResp(prev.url, prev.status), redirectChain: chain, blockedRedirect: { location: current, reason: (e as Error).message } };
      }
    }
    opts.onRequest?.(current);
    const res = await singleRequest(current, opts, policy, resolver);
    const location = header(res.headers, "location");
    if (res.status >= 300 && res.status < 400 && location) {
      const next = new URL(location, current).toString();
      chain.push({ url: current, status: res.status, location: next });
      current = next;
      continue;
    }
    return { ...res, redirectChain: chain };
  }
  throw new NetguardError("Zu viele Weiterleitungen", "OUT_OF_SCOPE");
}

function emptyResp(url: string, status: number) {
  return { url, status, headers: {}, body: "", truncated: false };
}

export function header(h: Record<string, string | string[]>, name: string): string | undefined {
  const v = h[name.toLowerCase()];
  return Array.isArray(v) ? v[0] : v;
}

function singleRequest(
  rawUrl: string,
  opts: GuardedRequestOptions,
  policy: NetguardPolicy,
  resolver: Resolver,
): Promise<Omit<GuardedResponse, "redirectChain">> {
  const url = new URL(rawUrl);
  const isHttps = url.protocol === "https:";
  const lib = isHttps ? https : http;
  const maxBody = opts.maxBodyBytes ?? 1_000_000;
  return new Promise((resolve, reject) => {
    const req = lib.request(
      url,
      {
        method: opts.method ?? "GET",
        headers: { "user-agent": "WebAudit-Security/0.1 (+autorisierte Pruefung)", accept: "*/*", ...(opts.headers ?? {}) },
        lookup: guardedLookup(policy, resolver) as never,
        agent: false,
        timeout: opts.timeoutMs ?? 15000,
        rejectUnauthorized: !(opts.allowInvalidCerts && process.env.NODE_ENV !== "production"),
      },
      (res) => {
        const chunks: Buffer[] = [];
        let size = 0;
        let truncated = false;
        res.on("data", (c: Buffer) => {
          if (size + c.length > maxBody) {
            truncated = true;
            chunks.push(c.subarray(0, Math.max(0, maxBody - size)));
            size = maxBody;
            res.destroy();
            return;
          }
          size += c.length;
          chunks.push(c);
        });
        const done = () =>
          resolve({
            url: rawUrl,
            status: res.statusCode ?? 0,
            headers: res.headers as Record<string, string | string[]>,
            body: Buffer.concat(chunks).toString("utf8"),
            truncated,
            remoteAddress: res.socket?.remoteAddress,
          });
        res.on("end", done);
        res.on("close", done);
        res.on("error", (e) => (truncated ? done() : reject(e)));
      },
    );
    req.on("timeout", () => req.destroy(new Error("Zeitüberschreitung")));
    req.on("error", reject);
    req.end();
  });
}

export type TlsInfo = {
  authorized: boolean;
  authorizationError?: string;
  protocol?: string | null;
  cipher?: string;
  subject?: string;
  issuer?: string;
  validFrom?: string;
  validTo?: string;
  daysRemaining?: number;
  subjectAltNames?: string;
};

/** Liest Zertifikatsinformationen (auch bei ungültigen Zertifikaten), mit Netzwerkschutz. */
export function inspectTls(hostname: string, port: number, policy: NetguardPolicy = loadPolicy(), resolver: Resolver = systemResolver): Promise<TlsInfo> {
  return new Promise((resolve, reject) => {
    const socket = tls.connect({
      host: hostname,
      port,
      servername: /^[\d.]+$|:/.test(hostname) ? undefined : hostname,
      rejectUnauthorized: false,
      lookup: guardedLookup(policy, resolver) as never,
      timeout: 10000,
    });
    socket.on("secureConnect", () => {
      const cert = socket.getPeerCertificate();
      const validTo = cert?.valid_to;
      const info: TlsInfo = {
        authorized: socket.authorized,
        authorizationError: socket.authorizationError ? String(socket.authorizationError) : undefined,
        protocol: socket.getProtocol(),
        cipher: socket.getCipher()?.name,
        subject: cert?.subject ? Object.entries(cert.subject).map(([k, v]) => `${k}=${v}`).join(", ") : undefined,
        issuer: cert?.issuer ? Object.entries(cert.issuer).map(([k, v]) => `${k}=${v}`).join(", ") : undefined,
        validFrom: cert?.valid_from,
        validTo,
        daysRemaining: validTo ? Math.floor((new Date(validTo).getTime() - Date.now()) / 86400000) : undefined,
        subjectAltNames: cert?.subjectaltname,
      };
      socket.end();
      resolve(info);
    });
    socket.on("timeout", () => socket.destroy(new Error("TLS-Zeitüberschreitung")));
    socket.on("error", reject);
  });
}
