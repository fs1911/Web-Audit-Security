import http from "node:http";
import net from "node:net";
import { describe, expect, it } from "vitest";
import { checkScope, normalizeScope, scopeToZapRegexes } from "../src/lib/security/scope";
import { EgressProxy } from "../src/lib/security/egress-proxy";
import { localPolicy, startServer } from "./helpers";

const scope = normalizeScope({ hosts: ["www.example.ch"], includePaths: ["/"], excludePaths: ["/admin", "re:\\.pdf$"] });
const pol = localPolicy([]);

describe("Scope", () => {
  it("lässt freigegebene Hosts und Pfade zu", () => {
    expect(checkScope("https://www.example.ch/produkte", scope, pol).inScope).toBe(true);
  });
  it("lehnt nicht verifizierte Subdomains ab (keine automatische Subdomain-Freigabe)", () => {
    expect(checkScope("https://api.example.ch/", scope, pol).inScope).toBe(false);
    expect(checkScope("https://example.ch/", scope, pol).inScope).toBe(false);
  });
  it("lehnt Wildcard-Hosts ab", () => {
    expect(() => normalizeScope({ hosts: ["*.example.ch"], includePaths: [], excludePaths: [] })).toThrow(/Wildcard/);
  });
  it("respektiert Ausschlüsse inkl. Kodierungs- und Gross/Klein-Tricks", () => {
    expect(checkScope("https://www.example.ch/admin/users", scope, pol).inScope).toBe(false);
    expect(checkScope("https://www.example.ch/ADMIN", scope, pol).inScope).toBe(false);
    expect(checkScope("https://www.example.ch/%61dmin", scope, pol).inScope).toBe(false);
    expect(checkScope("https://www.example.ch//admin", scope, pol).inScope).toBe(false);
    expect(checkScope("https://www.example.ch/docs/a.pdf", scope, pol).inScope).toBe(false);
  });
  it("verfolgt keine potentiell zustandsändernden Links", () => {
    expect(checkScope("https://www.example.ch/logout", scope, pol).inScope).toBe(false);
    expect(checkScope("https://www.example.ch/item?action=delete&id=4", scope, pol).inScope).toBe(false);
  });
  it("erzeugt ZAP-Regexe mit Standardausschlüssen", () => {
    const r = scopeToZapRegexes(scope, [443]);
    expect(r.include[0]).toContain("www\\.example\\.ch");
    expect(r.exclude.some((x) => x.includes("logout"))).toBe(true);
  });
});

function connect(proxyPort: number, target: string): Promise<string> {
  return new Promise((resolve, reject) => {
    const s = net.connect(proxyPort, "127.0.0.1", () => s.write(`CONNECT ${target} HTTP/1.1\r\nHost: ${target}\r\n\r\n`));
    s.once("data", (d) => {
      resolve(d.toString().split("\r\n")[0]!);
      s.destroy();
    });
    s.on("error", reject);
  });
}

function viaProxy(proxyPort: number, method: string, url: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port: proxyPort, method, path: url, headers: { host: new URL(url).host } }, (res) => {
      res.resume();
      resolve(res.statusCode ?? 0);
    });
    req.on("error", reject);
    req.end();
  });
}

describe("Egress-Proxy (für ZAP und Unterprozesse)", () => {
  it("erzwingt Scope, Methoden, IP-Prüfung und Request-Budget", async () => {
    let hits = 0;
    const target = await startServer((_req, res) => {
      hits++;
      res.end("ok");
    });
    const policy = localPolicy([target.port]);
    const proxy = new EgressProxy({ scope: { hosts: ["127.0.0.1"], includePaths: ["/"], excludePaths: ["/privat"] }, allowedMethods: ["GET", "HEAD"], maxRequests: 3, requestsPerSecond: 50, policy });
    const port = await proxy.listen();

    expect(await viaProxy(port, "GET", `http://127.0.0.1:${target.port}/`)).toBe(200);
    expect(await viaProxy(port, "POST", `http://127.0.0.1:${target.port}/`)).toBe(405);
    expect(await viaProxy(port, "GET", `http://127.0.0.1:${target.port}/privat/x`)).toBe(403);
    expect(await viaProxy(port, "GET", `http://127.0.0.1:${target.port}/logout`)).toBe(403);
    expect(await viaProxy(port, "GET", `http://example.org/`)).toBe(403);
    expect(await connect(port, "example.org:443")).toMatch(/403/);
    expect(await connect(port, "169.254.169.254:80")).toMatch(/403/);
    expect(await connect(port, `127.0.0.1:22`)).toMatch(/403/);
    expect(await connect(port, `127.0.0.1:${target.port}`)).toMatch(/200/);
    expect(await viaProxy(port, "GET", `http://127.0.0.1:${target.port}/b`)).toBe(200);
    // Budget (3) erschöpft
    expect(await viaProxy(port, "GET", `http://127.0.0.1:${target.port}/c`)).toBe(429);
    const stats = proxy.getStats();
    expect(stats.allowed).toBe(3);
    expect(stats.blocked).toBeGreaterThanOrEqual(7);
    expect(hits).toBe(2);
    await proxy.close();
    await target.close();
  });
});
