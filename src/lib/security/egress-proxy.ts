import http from "node:http";
import net from "node:net";
import type { AddressInfo } from "node:net";
import { loadPolicy, normalizeHostname, resolveSafe, type NetguardPolicy, type Resolver, systemResolver, validateUrl } from "./netguard";
import { checkScope, type Scope } from "./scope";

/**
 * Egress-Guard-Proxy: Einziger Weg, über den ZAP (und andere Unterprozesse) Ziele erreichen.
 *
 * - HTTP (absolute-form): voller Scope-Check inkl. Pfad, Ausschlüsse, Methoden-Allowlist.
 * - HTTPS (CONNECT): Host, Port und aufgelöste IP werden geprüft; der Tunnel wird auf die
 *   geprüfte IP aufgebaut. Pfade/Methoden innerhalb von TLS sind hier NICHT sichtbar und
 *   werden durch die ZAP-Konfiguration (Kontext, Spider ohne Formulare) begrenzt.
 * - Request-Budget und Rate-Limit pro Scan.
 */
export type EgressProxyOptions = {
  scope: Scope;
  allowedMethods: string[];
  maxRequests: number;
  requestsPerSecond: number;
  policy?: NetguardPolicy;
  resolver?: Resolver;
  onEvent?: (e: EgressEvent) => void;
};

export type EgressEvent =
  | { type: "allowed"; method: string; target: string; ip: string }
  | { type: "blocked"; method: string; target: string; reason: string };

export type EgressStats = { allowed: number; blocked: number; blockedSamples: { target: string; reason: string }[] };

export class EgressProxy {
  private server: http.Server;
  private stats: EgressStats = { allowed: 0, blocked: 0, blockedSamples: [] };
  private tokens: number;
  private lastRefill = Date.now();
  private sockets = new Set<net.Socket>();
  private closed = false;
  private readonly policy: NetguardPolicy;
  private readonly resolver: Resolver;

  constructor(private readonly opts: EgressProxyOptions) {
    this.policy = opts.policy ?? loadPolicy();
    this.resolver = opts.resolver ?? systemResolver;
    this.tokens = opts.requestsPerSecond;
    this.server = http.createServer((req, res) => void this.handleHttp(req, res));
    this.server.on("connect", (req, socket: net.Socket, head) => void this.handleConnect(req, socket, head));
    this.server.on("connection", (s) => {
      this.sockets.add(s);
      s.on("close", () => this.sockets.delete(s));
    });
  }

  async listen(): Promise<number> {
    await new Promise<void>((r) => this.server.listen(0, "127.0.0.1", r));
    return (this.server.address() as AddressInfo).port;
  }

  getStats(): EgressStats {
    return { ...this.stats, blockedSamples: [...this.stats.blockedSamples] };
  }

  async close(): Promise<void> {
    this.closed = true;
    for (const s of this.sockets) s.destroy();
    await new Promise<void>((r) => this.server.close(() => r()));
  }

  private block(method: string, target: string, reason: string) {
    this.stats.blocked++;
    if (this.stats.blockedSamples.length < 50) this.stats.blockedSamples.push({ target, reason });
    this.opts.onEvent?.({ type: "blocked", method, target, reason });
  }

  private async takeToken(): Promise<boolean> {
    if (this.closed) return false;
    if (this.stats.allowed >= this.opts.maxRequests) return false;
    for (;;) {
      const now = Date.now();
      const refill = ((now - this.lastRefill) / 1000) * this.opts.requestsPerSecond;
      if (refill > 0) {
        this.tokens = Math.min(this.opts.requestsPerSecond, this.tokens + refill);
        this.lastRefill = now;
      }
      if (this.tokens >= 1) {
        this.tokens -= 1;
        return true;
      }
      await new Promise((r) => setTimeout(r, Math.ceil(1000 / this.opts.requestsPerSecond)));
      if (this.closed) return false;
    }
  }

  private async handleConnect(req: http.IncomingMessage, client: net.Socket, head: Buffer) {
    const target = req.url ?? "";
    const m = target.match(/^\[?([^\]]+?)\]?:(\d+)$/);
    if (!m) {
      this.block("CONNECT", target, "Ungültiges CONNECT-Ziel");
      client.end("HTTP/1.1 400 Bad Request\r\n\r\n");
      return;
    }
    const host = normalizeHostname(m[1]!);
    const port = Number(m[2]);
    const decision = checkScope(`https://${host.includes(":") ? `[${host}]` : host}:${port}/`, this.opts.scope, this.policy, { stateChangingGuard: false });
    if (!decision.inScope) {
      this.block("CONNECT", target, decision.reason);
      client.end("HTTP/1.1 403 Forbidden\r\nX-WebAudit-Blocked: scope\r\n\r\n");
      return;
    }
    if (!(await this.takeToken())) {
      this.block("CONNECT", target, "Request-Budget erschöpft oder Scan beendet");
      client.end("HTTP/1.1 429 Too Many Requests\r\n\r\n");
      return;
    }
    let ip: string;
    try {
      ip = (await resolveSafe(host, this.policy, this.resolver)).address;
    } catch (e) {
      this.block("CONNECT", target, (e as Error).message);
      client.end("HTTP/1.1 403 Forbidden\r\nX-WebAudit-Blocked: ip\r\n\r\n");
      return;
    }
    this.stats.allowed++;
    this.opts.onEvent?.({ type: "allowed", method: "CONNECT", target, ip });
    const upstream = net.connect({ host: ip, port });
    upstream.on("connect", () => {
      client.write("HTTP/1.1 200 Connection Established\r\n\r\n");
      if (head.length) upstream.write(head);
      upstream.pipe(client);
      client.pipe(upstream);
    });
    const kill = () => {
      upstream.destroy();
      client.destroy();
    };
    upstream.on("error", kill);
    client.on("error", kill);
    this.sockets.add(upstream);
    upstream.on("close", () => this.sockets.delete(upstream));
  }

  private async handleHttp(req: http.IncomingMessage, res: http.ServerResponse) {
    const method = (req.method ?? "GET").toUpperCase();
    const target = req.url ?? "";
    if (!/^http:\/\//i.test(target)) {
      this.block(method, target, "Nur absolute http-URLs oder CONNECT erlaubt");
      res.writeHead(400).end();
      return;
    }
    if (!this.opts.allowedMethods.includes(method)) {
      this.block(method, target, `Methode ${method} ist im gewählten Prüfmodus nicht erlaubt`);
      res.writeHead(405, { "x-webaudit-blocked": "method" }).end();
      return;
    }
    const decision = checkScope(target, this.opts.scope, this.policy);
    if (!decision.inScope) {
      this.block(method, target, decision.reason);
      res.writeHead(403, { "x-webaudit-blocked": "scope" }).end();
      return;
    }
    if (!(await this.takeToken())) {
      this.block(method, target, "Request-Budget erschöpft oder Scan beendet");
      res.writeHead(429).end();
      return;
    }
    let ip: string;
    let v;
    try {
      v = validateUrl(target, this.policy);
      ip = (await resolveSafe(v.hostname, this.policy, this.resolver)).address;
    } catch (e) {
      this.block(method, target, (e as Error).message);
      res.writeHead(403, { "x-webaudit-blocked": "ip" }).end();
      return;
    }
    this.stats.allowed++;
    this.opts.onEvent?.({ type: "allowed", method, target, ip });
    const headers = { ...req.headers };
    delete headers["proxy-connection"];
    delete headers["proxy-authorization"];
    const upstream = http.request(
      { host: ip, port: v.port, method, path: v.url.pathname + v.url.search, headers: { ...headers, host: v.url.host }, agent: false, timeout: 30000 },
      (up) => {
        res.writeHead(up.statusCode ?? 502, up.headers);
        up.pipe(res);
      },
    );
    upstream.on("timeout", () => upstream.destroy(new Error("timeout")));
    upstream.on("error", () => {
      if (!res.headersSent) res.writeHead(502);
      res.end();
    });
    req.pipe(upstream);
  }
}
