import { describe, expect, it } from "vitest";
import { classifyIp } from "../src/lib/security/ip";
import { loadPolicy, resolveSafe, validateUrl, NetguardError, type Resolver } from "../src/lib/security/netguard";
import { guardedRequest } from "../src/lib/security/http";
import { localPolicy, startServer } from "./helpers";

const prod = loadPolicy({ NODE_ENV: "production", NETGUARD_TEST_ALLOW_CIDRS: "127.0.0.1/32", NETGUARD_TEST_ALLOW_PORTS: "8443" } as NodeJS.ProcessEnv);

describe("URL-Validierung", () => {
  it("akzeptiert öffentliche https-URLs", () => {
    expect(validateUrl("https://www.example.ch/pfad?x=1", prod).hostname).toBe("www.example.ch");
  });
  it.each([
    ["ftp://example.ch/", "SCHEME"],
    ["file:///etc/passwd", "SCHEME"],
    ["javascript:alert(1)", "SCHEME"],
    ["https://user:pass@example.ch/", "CREDENTIALS"],
    ["https://example.ch:8443/", "PORT"],
    ["http://example.ch:22/", "PORT"],
    ["http://localhost/", "HOSTNAME"],
    ["http://intranet/", "HOSTNAME"],
    ["http://db.internal/", "HOSTNAME"],
    ["http://metadata.google.internal/", "HOSTNAME"],
    ["http://127.0.0.1/", "BLOCKED_IP"],
    ["http://10.1.2.3/", "BLOCKED_IP"],
    ["http://172.16.5.4/", "BLOCKED_IP"],
    ["http://192.168.1.1/", "BLOCKED_IP"],
    ["http://169.254.169.254/latest/meta-data/", "BLOCKED_IP"],
    ["http://100.64.0.1/", "BLOCKED_IP"],
    ["http://0.0.0.0/", "BLOCKED_IP"],
    ["http://[::1]/", "BLOCKED_IP"],
    ["http://[fe80::1]/", "BLOCKED_IP"],
    ["http://[fd00:ec2::254]/", "BLOCKED_IP"],
    ["http://[fc00::5]/", "BLOCKED_IP"],
    ["http://[::ffff:127.0.0.1]/", "BLOCKED_IP"],
    ["http://[::ffff:7f00:1]/", "BLOCKED_IP"],
    ["http://[64:ff9b::a00:1]/", "BLOCKED_IP"],
    ["http://[2001:db8::1]/", "BLOCKED_IP"],
    ["http://[ff02::1]/", "BLOCKED_IP"],
  ])("lehnt %s ab (%s)", (url, code) => {
    try {
      validateUrl(url, prod);
      expect.fail("hätte abgelehnt werden müssen");
    } catch (e) {
      expect(e).toBeInstanceOf(NetguardError);
      expect((e as NetguardError).code).toBe(code);
    }
  });
  it.each(["http://2130706433/", "http://0x7f000001/", "http://0177.0.0.1/", "http://127.1/", "http://0x7f.0.0.1/", "http://017700000001/", "http://127.000.000.001/"])(
    "erkennt alternative IP-Schreibweise %s als Loopback",
    (url) => {
      expect(() => validateUrl(url, prod)).toThrowError(NetguardError);
    },
  );
  it("ignoriert Test-Ausnahmen in production", () => {
    expect(() => validateUrl("https://127.0.0.1:8443/", prod)).toThrow();
    expect(validateUrl("https://127.0.0.1:8443/", localPolicy([8443])).hostname).toBe("127.0.0.1");
  });
  it("blockiert Zeichen zur URL-Verwirrung", () => {
    expect(() => validateUrl("https://example.ch\\@evil.ch/", prod)).toThrow();
    expect(() => validateUrl("https://exa mple.ch/", prod)).toThrow();
  });
});

describe("IP-Klassifikation", () => {
  it("erlaubt öffentliche Adressen", () => {
    expect(classifyIp("8.8.8.8").allowed).toBe(true);
    expect(classifyIp("2606:4700:4700::1111").allowed).toBe(true);
  });
  it("blockiert 6to4 und Teredo", () => {
    expect(classifyIp("2002:7f00:1::").allowed).toBe(false);
    expect(classifyIp("2001:0:4136:e378::1").allowed).toBe(false);
  });
});

describe("DNS-Prüfung und Rebinding", () => {
  it("lehnt ab, wenn irgendeine aufgelöste Adresse intern ist", async () => {
    const r: Resolver = async () => [{ address: "93.184.215.14", family: 4 }, { address: "10.0.0.7", family: 4 }];
    await expect(resolveSafe("mixed.example.ch", prod, r)).rejects.toThrow(/blockierte Adresse/);
  });
  it("lehnt Hostnamen ab, die auf Cloud-Metadaten zeigen", async () => {
    const r: Resolver = async () => [{ address: "169.254.169.254", family: 4 }];
    await expect(resolveSafe("evil.example.ch", prod, r)).rejects.toThrow();
  });
  it("prüft die DNS-Auflösung bei JEDEM Verbindungsaufbau (Rebinding)", async () => {
    const srv = await startServer((_req, res) => res.end("ok"));
    const policy = localPolicy([srv.port]);
    let calls = 0;
    // Erst erlaubtes Ziel, dann interne Adresse – klassisches DNS-Rebinding
    const resolver: Resolver = async () => (++calls === 1 ? [{ address: "127.0.0.1", family: 4 }] : [{ address: "10.0.0.5", family: 4 }]);
    const url = `http://rebind.example.ch:${srv.port}/`;
    const first = await guardedRequest(url, { policy, resolver });
    expect(first.status).toBe(200);
    await expect(guardedRequest(url, { policy, resolver })).rejects.toThrow(/blockierte Adresse/);
    expect(calls).toBe(2);
    await srv.close();
  });
});

describe("Redirect-Schutz", () => {
  it("folgt Weiterleitungen nicht auf fremde Hosts", async () => {
    const srv = await startServer((req, res) => {
      res.writeHead(302, { location: "http://evil.example.org/steal" });
      res.end();
    });
    const policy = localPolicy([srv.port]);
    const res = await guardedRequest(`http://127.0.0.1:${srv.port}/`, { policy, scope: { hosts: ["127.0.0.1"], includePaths: ["/"], excludePaths: [] } });
    expect(res.blockedRedirect?.location).toBe("http://evil.example.org/steal");
    expect(res.blockedRedirect?.reason).toMatch(/nicht freigegeben/);
    await srv.close();
  });
  it("blockiert Weiterleitungen auf interne Adressen auch ohne Scope", async () => {
    const srv = await startServer((_req, res) => {
      res.writeHead(301, { location: "http://169.254.169.254/latest/meta-data/" });
      res.end();
    });
    const res = await guardedRequest(`http://127.0.0.1:${srv.port}/`, { policy: localPolicy([srv.port]) });
    expect(res.blockedRedirect?.reason).toMatch(/Link-Local|blockiert/);
    await srv.close();
  });
});
