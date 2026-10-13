import { guardedRequest, header, inspectTls, type GuardedResponse } from "../../lib/security/http";
import type { NetguardPolicy } from "../../lib/security/netguard";
import type { Scope } from "../../lib/security/scope";
import type { CoverageEntry, RawFinding, Severity, FindingKind, Confidence } from "../../lib/findings/types";
import { refsForCheck } from "../../lib/catalog";
import { redact } from "../../lib/security/redact";

export const NATIVE_TOOL = "WebAudit Native Checks";
export const NATIVE_VERSION = "0.1.0";

type Ctx = {
  baseUrl: string;
  scope: Scope;
  policy: NetguardPolicy;
  authContext: string;
  extraHeaders?: Record<string, string>;
  knownSecrets: string[];
  allowInvalidCerts?: boolean;
  signal?: AbortSignal;
  log: (msg: string) => void;
};

export type NativeResult = { findings: RawFinding[]; coverage: CoverageEntry[]; pagesFetched: number };

function finding(ctx: Ctx, checkId: string, p: { title: string; category: string; kind: FindingKind; severity: Severity; confidence: Confidence; url?: string; evidence: string; description: string; remediation: string; impact?: string; limitations?: string; cweId?: number; parameter?: string }): RawFinding {
  return {
    title: p.title,
    category: p.category,
    kind: p.kind,
    severity: p.severity,
    confidence: p.confidence,
    checkId,
    affectedUrl: p.url,
    parameter: p.parameter,
    method: "GET",
    tool: NATIVE_TOOL,
    toolVersion: NATIVE_VERSION,
    ruleId: checkId,
    authContext: ctx.authContext,
    evidence: redact(p.evidence, { knownSecrets: ctx.knownSecrets }),
    description: p.description,
    remediation: p.remediation,
    impact: p.impact,
    limitations: p.limitations,
    references: refsForCheck(checkId),
    externalLinks: [],
    cweId: p.cweId,
  };
}

function headerDump(res: GuardedResponse, names: string[]): string {
  return names.map((n) => `${n}: ${header(res.headers, n) ?? "(nicht gesetzt)"}`).join("\n");
}

function setCookies(res: GuardedResponse): string[] {
  const v = res.headers["set-cookie"];
  return Array.isArray(v) ? v : v ? [v] : [];
}

type ParsedCookie = { name: string; attrs: Map<string, string | true>; raw: string };
export function parseSetCookie(raw: string): ParsedCookie {
  const parts = raw.split(";").map((s) => s.trim());
  const first = parts.shift() ?? "";
  const name = first.split("=")[0]!.trim();
  const attrs = new Map<string, string | true>();
  for (const p of parts) {
    const [k, ...rest] = p.split("=");
    if (k) attrs.set(k.trim().toLowerCase(), rest.length ? rest.join("=").trim() : true);
  }
  return { name, attrs, raw };
}

const SESSIONISH = /(sess|sid|auth|token|login|jwt|remember)/i;

export function analyzeHeaders(ctx: Ctx, res: GuardedResponse, isHttps: boolean): { findings: RawFinding[]; coverage: CoverageEntry[] } {
  const f: RawFinding[] = [];
  const cov: CoverageEntry[] = [];
  const url = res.url;
  const ev = (names: string[]) => `GET ${url} → Status ${res.status}\n${headerDump(res, names)}`;

  // HSTS
  if (isHttps) {
    const hsts = header(res.headers, "strict-transport-security");
    const maxAge = Number(hsts?.match(/max-age=(\d+)/i)?.[1] ?? NaN);
    if (!hsts) {
      f.push(finding(ctx, "WA-HDR-01", { title: "Strict-Transport-Security-Header fehlt", category: "HTTP-Header", kind: "configuration", severity: "low", confidence: "high", url, evidence: ev(["strict-transport-security"]), cweId: 319,
        description: "Die Antwort enthält keinen HSTS-Header. Browser können dadurch bei späteren Besuchen zunächst eine unverschlüsselte Verbindung aufbauen.",
        impact: "Ermöglicht in bestimmten Netzwerksituationen (z. B. öffentliches WLAN) SSL-Stripping-Angriffe beim ersten Aufruf ohne https://.",
        remediation: "Header «Strict-Transport-Security: max-age=31536000; includeSubDomains» auf allen HTTPS-Antworten setzen (includeSubDomains nur, wenn alle Subdomains HTTPS unterstützen)." }));
    } else if (!Number.isFinite(maxAge) || maxAge < 31536000) {
      f.push(finding(ctx, "WA-HDR-01", { title: "HSTS max-age kürzer als ein Jahr", category: "HTTP-Header", kind: "configuration", severity: "low", confidence: "high", url, evidence: ev(["strict-transport-security"]), cweId: 319,
        description: `Der HSTS-Header ist gesetzt, aber max-age (${Number.isFinite(maxAge) ? maxAge : "ungültig"}) liegt unter einem Jahr (31536000 Sekunden).`,
        remediation: "max-age auf mindestens 31536000 erhöhen." }));
    }
    cov.push({ checkId: "WA-HDR-01", state: "tested", method: "Header der Startseite", evidence: headerDump(res, ["strict-transport-security"]) });
  } else {
    cov.push({ checkId: "WA-HDR-01", state: "not_applicable", limitation: "Ziel wird nicht über HTTPS ausgeliefert" });
  }

  // CSP
  const csp = header(res.headers, "content-security-policy");
  if (!csp) {
    f.push(finding(ctx, "WA-HDR-02", { title: "Content-Security-Policy-Header fehlt", category: "HTTP-Header", kind: "configuration", severity: "low", confidence: "high", url, evidence: ev(["content-security-policy", "content-security-policy-report-only"]), cweId: 693,
      description: "Es ist keine Content Security Policy gesetzt. Eine CSP begrenzt die Auswirkungen von Cross-Site-Scripting und eingeschleusten Inhalten.",
      remediation: "Eine restriktive CSP einführen, mindestens: default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'. Zunächst im Report-Only-Modus testen." }));
  } else {
    const missing = ["object-src", "base-uri"].filter((d) => !new RegExp(`(^|;)\\s*${d}\\s`, "i").test(csp));
    const objOk = /object-src\s+'none'/i.test(csp) || (!/object-src/i.test(csp) && /default-src\s+'none'/i.test(csp));
    if (missing.length || !objOk) {
      f.push(finding(ctx, "WA-HDR-02", { title: "Content Security Policy ohne object-src/base-uri 'none'", category: "HTTP-Header", kind: "configuration", severity: "low", confidence: "medium", url, evidence: ev(["content-security-policy"]), cweId: 693,
        description: `Die CSP ist gesetzt, schränkt aber ${missing.length ? missing.join(" und ") : "object-src"} nicht auf 'none' ein.`,
        remediation: "object-src 'none' und base-uri 'none' (oder 'self') ergänzen." }));
    }
  }
  cov.push({ checkId: "WA-HDR-02", state: "tested", method: "Header der Startseite", evidence: headerDump(res, ["content-security-policy"]) });

  // X-Content-Type-Options
  if ((header(res.headers, "x-content-type-options") ?? "").toLowerCase() !== "nosniff") {
    f.push(finding(ctx, "WA-HDR-03", { title: "Header X-Content-Type-Options fehlt", category: "HTTP-Header", kind: "configuration", severity: "low", confidence: "high", url, evidence: ev(["x-content-type-options", "content-type"]), cweId: 693,
      description: "Ohne «X-Content-Type-Options: nosniff» können Browser den Inhaltstyp erraten (MIME-Sniffing) und Inhalte unerwartet als Skript oder HTML interpretieren.",
      remediation: "Header «X-Content-Type-Options: nosniff» auf allen Antworten setzen." }));
  }
  cov.push({ checkId: "WA-HDR-03", state: "tested", method: "Header der Startseite", evidence: headerDump(res, ["x-content-type-options"]) });

  // Referrer-Policy
  const rp = header(res.headers, "referrer-policy");
  if (!rp || /unsafe-url|no-referrer-when-downgrade/i.test(rp)) {
    f.push(finding(ctx, "WA-HDR-04", { title: rp ? "Schwache Referrer-Policy" : "Referrer-Policy nicht gesetzt", category: "HTTP-Header", kind: rp ? "configuration" : "informational", severity: rp ? "low" : "info", confidence: "high", url, evidence: ev(["referrer-policy"]), cweId: 200,
      description: rp ? `Die Referrer-Policy «${rp}» kann vollständige URLs inkl. Parametern an Dritte übermitteln.` : "Es ist keine Referrer-Policy gesetzt. Aktuelle Browser verwenden standardmässig «strict-origin-when-cross-origin»; ältere Browser können vollständige URLs übermitteln.",
      remediation: "Header «Referrer-Policy: strict-origin-when-cross-origin» (oder strenger) setzen." }));
  }
  cov.push({ checkId: "WA-HDR-04", state: "tested", method: "Header der Startseite", evidence: headerDump(res, ["referrer-policy"]) });

  // Clickjacking
  const fa = csp && /frame-ancestors/i.test(csp);
  const xfo = header(res.headers, "x-frame-options");
  if (!fa) {
    f.push(finding(ctx, "WA-HDR-05", { title: xfo ? "Clickjacking-Schutz nur über veralteten X-Frame-Options-Header" : "Kein Schutz vor Clickjacking", category: "HTTP-Header", kind: "configuration", severity: xfo ? "info" : "low", confidence: "high", url, evidence: ev(["content-security-policy", "x-frame-options"]), cweId: 1021,
      description: xfo ? "Die Seite verwendet X-Frame-Options, aber keine CSP-Direktive frame-ancestors. X-Frame-Options gilt als veraltet." : "Die Seite kann in fremde Seiten eingebettet werden. Angreifende können Nutzende so zu ungewollten Klicks verleiten.",
      remediation: "CSP-Direktive «frame-ancestors 'none'» (oder 'self') setzen; X-Frame-Options kann zusätzlich für alte Browser bleiben." }));
  }
  cov.push({ checkId: "WA-HDR-05", state: "tested", method: "Header der Startseite", evidence: headerDump(res, ["x-frame-options"]) + (fa ? "\nCSP frame-ancestors gesetzt" : "") });

  // Server-Versionsangaben
  const server = header(res.headers, "server");
  const xpb = header(res.headers, "x-powered-by");
  const versioned = [server, xpb].filter((v): v is string => Boolean(v && /\d/.test(v)));
  if (versioned.length || xpb) {
    f.push(finding(ctx, "WA-HDR-06", { title: "Header verraten Software oder Versionen", category: "Informationspreisgabe", kind: "configuration", severity: "low", confidence: "high", url, evidence: ev(["server", "x-powered-by"]), cweId: 200,
      description: "Server- oder X-Powered-By-Header nennen eingesetzte Software und teilweise deren Version. Das erleichtert gezielte Angriffe auf bekannte Schwachstellen.",
      remediation: "X-Powered-By entfernen und den Server-Header auf eine generische Angabe ohne Version reduzieren." }));
  }
  cov.push({ checkId: "WA-HDR-06", state: "tested", method: "Header der Startseite", evidence: headerDump(res, ["server", "x-powered-by"]) });

  // COOP (Level 3 → Information)
  if (!header(res.headers, "cross-origin-opener-policy")) {
    f.push(finding(ctx, "WA-HDR-08", { title: "Cross-Origin-Opener-Policy nicht gesetzt", category: "HTTP-Header", kind: "informational", severity: "info", confidence: "high", url, evidence: ev(["cross-origin-opener-policy"]),
      description: "Ohne COOP teilt die Seite ihren Browsing-Kontext mit fremden Fenstern, die sie öffnen. Gemäss ASVS ist dies eine Level-3-Anforderung.",
      remediation: "«Cross-Origin-Opener-Policy: same-origin» setzen, sofern keine Popups mit fremden Seiten kommunizieren müssen." }));
  }
  cov.push({ checkId: "WA-HDR-08", state: "tested", method: "Header der Startseite" });

  // Cookies
  const cookies = setCookies(res).map(parseSetCookie);
  if (cookies.length === 0) {
    for (const id of ["WA-CK-01", "WA-CK-02", "WA-CK-03", "WA-CK-04"]) cov.push({ checkId: id, state: "not_applicable", limitation: "Auf den nativ geprüften Seiten wurden keine Cookies gesetzt" });
  } else {
    for (const c of cookies) {
      const sessionish = SESSIONISH.test(c.name);
      const cev = `GET ${url}\nSet-Cookie: ${redact(c.raw, { knownSecrets: ctx.knownSecrets })}`;
      if (isHttps && !c.attrs.has("secure")) {
        f.push(finding(ctx, "WA-CK-01", { title: `Cookie «${c.name}» ohne Secure-Attribut`, category: "Cookies", kind: "configuration", severity: sessionish ? "medium" : "low", confidence: "high", url, parameter: c.name, evidence: cev, cweId: 614,
          description: "Das Cookie kann auch über unverschlüsselte HTTP-Verbindungen übertragen werden.",
          remediation: "Attribut «Secure» setzen; für Sitzungscookies zusätzlich das Präfix «__Host-» verwenden." }));
      }
      if (!c.attrs.has("httponly")) {
        f.push(finding(ctx, "WA-CK-02", { title: `Cookie «${c.name}» ohne HttpOnly-Attribut`, category: "Cookies", kind: sessionish ? "configuration" : "informational", severity: sessionish ? "medium" : "info", confidence: sessionish ? "medium" : "low", url, parameter: c.name, evidence: cev, cweId: 1004,
          description: sessionish ? "Das Cookie wirkt wie ein Sitzungs- oder Authentifizierungscookie und ist für JavaScript lesbar. Bei einer XSS-Lücke könnte es ausgelesen werden." : "Das Cookie ist für JavaScript lesbar. Ob das beabsichtigt ist, kann nicht automatisch beurteilt werden.",
          remediation: "Für alle Cookies, die nicht von Skripten gelesen werden müssen, «HttpOnly» setzen.",
          limitations: "Ob das Cookie von clientseitigem Code benötigt wird, wurde nicht geprüft." }));
      }
      const ss = c.attrs.get("samesite");
      if (!ss || (typeof ss === "string" && ss.toLowerCase() === "none" && !c.attrs.has("secure"))) {
        f.push(finding(ctx, "WA-CK-03", { title: `Cookie «${c.name}» ohne wirksames SameSite-Attribut`, category: "Cookies", kind: "configuration", severity: "low", confidence: "medium", url, parameter: c.name, evidence: cev, cweId: 1275,
          description: ss ? "SameSite=None ohne Secure wird von Browsern abgelehnt oder bietet keinen CSRF-Schutz." : "Ohne explizites SameSite-Attribut hängt das Verhalten vom Browser ab.",
          remediation: "SameSite=Lax (Standard) oder Strict setzen; None nur mit Secure und nur wenn seitenübergreifende Nutzung nötig ist." }));
      }
      if (sessionish && isHttps && !c.name.startsWith("__Host-") && !c.name.startsWith("__Secure-")) {
        f.push(finding(ctx, "WA-CK-04", { title: `Sitzungscookie «${c.name}» ohne __Host-/__Secure-Präfix`, category: "Cookies", kind: "informational", severity: "info", confidence: "medium", url, parameter: c.name, evidence: cev,
          description: "Cookie-Präfixe verhindern, dass Subdomains oder unverschlüsselte Verbindungen das Cookie überschreiben.",
          remediation: "Sitzungscookies als «__Host-<name>» mit Secure, Path=/ und ohne Domain-Attribut setzen." }));
      }
    }
    for (const id of ["WA-CK-01", "WA-CK-02", "WA-CK-03", "WA-CK-04"]) cov.push({ checkId: id, state: "tested", method: `${cookies.length} Cookie(s) der Startseite`, evidence: cookies.map((c) => c.name).join(", ") });
  }

  // Mixed Content
  if (isHttps && /text\/html/i.test(header(res.headers, "content-type") ?? "")) {
    const active: string[] = [];
    const passive: string[] = [];
    const re = /<(script|iframe|link|img|audio|video|source|embed|object)\b[^>]*?\s(?:src|href|data)\s*=\s*["'](http:\/\/[^"']+)["']/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(res.body))) {
      const tag = m[1]!.toLowerCase();
      if (tag === "link" && !/rel\s*=\s*["']?stylesheet/i.test(m[0])) continue;
      (["script", "iframe", "link", "embed", "object"].includes(tag) ? active : passive).push(`<${tag}> ${m[2]}`);
    }
    if (active.length || passive.length) {
      f.push(finding(ctx, "WA-MC-01", { title: active.length ? "Aktive gemischte Inhalte (HTTP-Skripte/Frames auf HTTPS-Seite)" : "Passive gemischte Inhalte (HTTP-Bilder/Medien auf HTTPS-Seite)", category: "Transportverschlüsselung", kind: "configuration", severity: active.length ? "medium" : "low", confidence: "high", url, cweId: 319,
        evidence: `GET ${url}\n${[...active, ...passive].slice(0, 10).join("\n")}`,
        description: active.length ? "Die HTTPS-Seite bindet Skripte, Stylesheets oder Frames über HTTP ein. Moderne Browser blockieren diese meist; wo nicht, können sie manipuliert werden." : "Die HTTPS-Seite lädt Bilder oder Medien über HTTP. Diese können mitgelesen oder ausgetauscht werden.",
        remediation: "Alle eingebundenen Ressourcen über HTTPS laden; zusätzlich CSP «upgrade-insecure-requests» erwägen." }));
    }
    cov.push({ checkId: "WA-MC-01", state: "tested", method: "Statische HTML-Analyse der Startseite" });
  } else {
    cov.push({ checkId: "WA-MC-01", state: isHttps ? "not_applicable" : "not_applicable", limitation: isHttps ? "Startseite ist kein HTML" : "Ziel nicht über HTTPS" });
  }
  return { findings: f, coverage: cov };
}

export async function runNativeChecks(ctx: Ctx): Promise<NativeResult> {
  const findings: RawFinding[] = [];
  const coverage: CoverageEntry[] = [];
  let pages = 0;
  const base = new URL(ctx.baseUrl);
  const isHttps = base.protocol === "https:";
  const req = (url: string, extra?: Record<string, string>) => {
    if (ctx.signal?.aborted) throw new Error("Abgebrochen");
    pages++;
    return guardedRequest(url, { scope: ctx.scope, policy: ctx.policy, headers: { ...(ctx.extraHeaders ?? {}), ...(extra ?? {}) }, allowInvalidCerts: ctx.allowInvalidCerts, maxRedirects: 5 });
  };

  // 1) TLS
  if (isHttps) {
    try {
      const tlsInfo = await inspectTls(base.hostname, Number(base.port || 443), ctx.policy);
      const tev = [`Protokoll: ${tlsInfo.protocol}`, `Cipher: ${tlsInfo.cipher}`, `Subjekt: ${tlsInfo.subject}`, `Aussteller: ${tlsInfo.issuer}`, `Gültig bis: ${tlsInfo.validTo}`, `SAN: ${tlsInfo.subjectAltNames}`, `Vertrauenswürdig: ${tlsInfo.authorized ? "ja" : `nein (${tlsInfo.authorizationError})`}`].join("\n");
      if (!tlsInfo.authorized) {
        findings.push(finding(ctx, "WA-TLS-01", { title: "TLS-Zertifikat nicht vertrauenswürdig", category: "Transportverschlüsselung", kind: "vulnerability", severity: "high", confidence: "confirmed", url: ctx.baseUrl, evidence: tev, cweId: 295,
          description: `Das Zertifikat konnte nicht gegen vertrauenswürdige Zertifizierungsstellen validiert werden (${tlsInfo.authorizationError}). Browser zeigen eine Warnung; Nutzende gewöhnen sich an das Wegklicken.`,
          remediation: "Ein öffentlich vertrauenswürdiges Zertifikat (z. B. Let's Encrypt) mit vollständiger Zertifikatskette und passendem Hostnamen einsetzen." }));
      }
      coverage.push({ checkId: "WA-TLS-01", state: "tested", method: "TLS-Handshake", evidence: tev });
      if (tlsInfo.protocol && !/TLSv1\.[23]/.test(tlsInfo.protocol)) {
        findings.push(finding(ctx, "WA-TLS-02", { title: `Veraltete TLS-Version ausgehandelt (${tlsInfo.protocol})`, category: "Transportverschlüsselung", kind: "configuration", severity: "medium", confidence: "confirmed", url: ctx.baseUrl, evidence: tev, cweId: 326,
          description: "Der Server handelt mit einem modernen Client eine veraltete TLS-Version aus.",
          remediation: "Nur TLS 1.2 und 1.3 aktivieren." }));
      }
      coverage.push({ checkId: "WA-TLS-02", state: "tested", method: "Ausgehandelte Version", evidence: `Protokoll: ${tlsInfo.protocol}`, limitation: "Akzeptanz veralteter Versionen nicht geprüft" });
      if (tlsInfo.daysRemaining !== undefined && tlsInfo.daysRemaining < 30) {
        findings.push(finding(ctx, "WA-TLS-03", { title: tlsInfo.daysRemaining < 0 ? "TLS-Zertifikat abgelaufen" : `TLS-Zertifikat läuft in ${tlsInfo.daysRemaining} Tagen ab`, category: "Transportverschlüsselung", kind: "configuration", severity: tlsInfo.daysRemaining < 0 ? "high" : "low", confidence: "confirmed", url: ctx.baseUrl, evidence: tev, cweId: 298,
          description: "Ein abgelaufenes Zertifikat führt zu Browserwarnungen und Verbindungsabbrüchen.",
          remediation: "Zertifikat erneuern und automatische Erneuerung einrichten (z. B. ACME)." }));
      }
      coverage.push({ checkId: "WA-TLS-03", state: "tested", method: "Zertifikatsablauf", evidence: `Gültig bis: ${tlsInfo.validTo}` });
    } catch (e) {
      ctx.log(`TLS-Prüfung fehlgeschlagen: ${(e as Error).message}`);
      for (const id of ["WA-TLS-01", "WA-TLS-02", "WA-TLS-03"]) coverage.push({ checkId: id, state: "error", limitation: (e as Error).message });
    }
  } else {
    findings.push(finding(ctx, "WA-TLS-01", { title: "Website wird ohne HTTPS geprüft", category: "Transportverschlüsselung", kind: "configuration", severity: "medium", confidence: "confirmed", url: ctx.baseUrl, evidence: `Basis-URL: ${ctx.baseUrl}`, cweId: 319,
      description: "Die hinterlegte Basis-URL verwendet HTTP. Inhalte und Zugangsdaten werden unverschlüsselt übertragen.",
      remediation: "HTTPS einrichten und die Basis-URL auf https:// umstellen." }));
    coverage.push({ checkId: "WA-TLS-01", state: "tested", method: "Basis-URL-Schema" });
    coverage.push({ checkId: "WA-TLS-02", state: "not_applicable", limitation: "Kein HTTPS" });
    coverage.push({ checkId: "WA-TLS-03", state: "not_applicable", limitation: "Kein HTTPS" });
  }

  // 2) Startseite + Header + Cookies + Mixed Content
  let main: GuardedResponse | null = null;
  try {
    main = await req(ctx.baseUrl);
    if (main.blockedRedirect) {
      ctx.log(`Weiterleitung ausserhalb des Scopes blockiert: ${main.blockedRedirect.location} (${main.blockedRedirect.reason})`);
      coverage.push({ checkId: "WA-CRAWL-01", state: "error", limitation: `Startseite leitet auf ein nicht freigegebenes Ziel weiter: ${main.blockedRedirect.location}` });
    } else {
      const r = analyzeHeaders(ctx, main, main.url.startsWith("https:"));
      findings.push(...r.findings);
      coverage.push(...r.coverage);
    }
  } catch (e) {
    ctx.log(`Startseite nicht abrufbar: ${(e as Error).message}`);
    for (const id of ["WA-HDR-01", "WA-HDR-02", "WA-HDR-03", "WA-HDR-04", "WA-HDR-05", "WA-HDR-06", "WA-HDR-08", "WA-CK-01", "WA-CK-02", "WA-CK-03", "WA-CK-04", "WA-MC-01"]) {
      coverage.push({ checkId: id, state: "error", limitation: `Startseite nicht abrufbar: ${(e as Error).message}` });
    }
  }

  // 3) CORS-Beobachtung
  try {
    const probeOrigin = "https://webaudit-cors-probe.invalid";
    const cr = await req(ctx.baseUrl, { origin: probeOrigin });
    const acao = header(cr.headers, "access-control-allow-origin");
    const acac = header(cr.headers, "access-control-allow-credentials");
    if (acao === probeOrigin || (acao === "*" && acac?.toLowerCase() === "true")) {
      findings.push(finding(ctx, "WA-HDR-07", { title: acao === probeOrigin ? "CORS spiegelt beliebige Origins" : "CORS-Wildcard mit Credentials", category: "HTTP-Header", kind: acac?.toLowerCase() === "true" ? "configuration" : "suspicion", severity: acac?.toLowerCase() === "true" ? "medium" : "low", confidence: "medium", url: cr.url, cweId: 942,
        evidence: `GET ${cr.url} mit Origin: ${probeOrigin}\nAccess-Control-Allow-Origin: ${acao}\nAccess-Control-Allow-Credentials: ${acac ?? "(nicht gesetzt)"}`,
        description: "Die Anwendung erlaubt Cross-Origin-Zugriffe von beliebigen Origins. In Kombination mit Credentials können fremde Websites Daten im Namen angemeldeter Nutzender lesen.",
        remediation: "Access-Control-Allow-Origin nur für eine feste Allowlist vertrauenswürdiger Origins setzen; Credentials nur, wenn zwingend nötig.",
        limitations: "Nur die Startseite geprüft; API-Endpunkte können sich anders verhalten." }));
    }
    coverage.push({ checkId: "WA-HDR-07", state: "tested", method: "GET mit fremdem Origin-Header", evidence: `ACAO: ${acao ?? "(nicht gesetzt)"}` });
  } catch (e) {
    coverage.push({ checkId: "WA-HDR-07", state: "error", limitation: (e as Error).message });
  }

  // 4) HTTP → HTTPS
  if (isHttps) {
    const probePort = base.port && base.port !== "443" ? process.env.NODE_ENV !== "production" ? process.env.WEBAUDIT_HTTP_PROBE_PORT : undefined : "80";
    if (!probePort) {
      coverage.push({ checkId: "WA-HTTP-01", state: "not_tested", limitation: "HTTPS läuft auf einem Nicht-Standard-Port; zugehöriger HTTP-Port unbekannt" });
    } else {
      const httpUrl = `http://${base.hostname}${probePort === "80" ? "" : `:${probePort}`}/`;
      try {
        const hr = await guardedRequest(httpUrl, { scope: ctx.scope, policy: ctx.policy, maxRedirects: 0, allowInvalidCerts: ctx.allowInvalidCerts });
        pages++;
        const loc = header(hr.headers, "location");
        const redirectsToHttps = hr.status >= 300 && hr.status < 400 && loc?.startsWith(`https://${base.hostname}`);
        const ev = `GET ${httpUrl} → Status ${hr.status}${loc ? `\nLocation: ${loc}` : ""}`;
        if (!redirectsToHttps) {
          findings.push(finding(ctx, "WA-HTTP-01", { title: "Keine Weiterleitung von HTTP auf HTTPS", category: "Transportverschlüsselung", kind: "configuration", severity: "medium", confidence: "confirmed", url: httpUrl, evidence: ev, cweId: 319,
            description: "Die Website ist über unverschlüsseltes HTTP erreichbar, ohne auf HTTPS weiterzuleiten.",
            remediation: "Alle HTTP-Anfragen mit Status 301/308 auf die HTTPS-Variante derselben URL weiterleiten und HSTS setzen." }));
        }
        coverage.push({ checkId: "WA-HTTP-01", state: "tested", method: "GET auf Port " + probePort, evidence: ev });
      } catch (e) {
        const msg = (e as Error).message;
        // Nicht erreichbarer HTTP-Port ist kein Befund
        coverage.push({ checkId: "WA-HTTP-01", state: "tested", method: "GET auf Port " + probePort, evidence: `HTTP nicht erreichbar: ${msg}` });
      }
    }
  } else {
    coverage.push({ checkId: "WA-HTTP-01", state: "not_applicable", limitation: "Ziel nicht über HTTPS" });
  }

  // 5) Gezielte Einzelabfragen
  try {
    const gitUrl = new URL("/.git/HEAD", ctx.baseUrl).toString();
    const g = await req(gitUrl);
    if (g.status === 200 && /^ref:\s*refs\//m.test(g.body)) {
      findings.push(finding(ctx, "WA-CFG-01", { title: "Git-Repository-Daten öffentlich abrufbar", category: "Informationspreisgabe", kind: "vulnerability", severity: "high", confidence: "confirmed", url: gitUrl, cweId: 527,
        evidence: `GET ${gitUrl} → Status 200\n${g.body.slice(0, 80)}`,
        description: "Das .git-Verzeichnis ist über den Webserver abrufbar. Damit lassen sich oft der vollständige Quellcode und eingecheckte Geheimnisse rekonstruieren.",
        impact: "Offenlegung von Quellcode, Konfiguration und möglicherweise Zugangsdaten.",
        remediation: "Zugriff auf /.git/ im Webserver sperren und das Verzeichnis nicht mit ausliefern; eingecheckte Secrets rotieren." }));
    }
    coverage.push({ checkId: "WA-CFG-01", state: "tested", method: "GET /.git/HEAD", evidence: `Status ${g.status}` });
  } catch (e) {
    coverage.push({ checkId: "WA-CFG-01", state: "error", limitation: (e as Error).message });
  }
  try {
    const stUrl = new URL("/.well-known/security.txt", ctx.baseUrl).toString();
    const s = await req(stUrl);
    const ok = s.status === 200 && /^contact:/im.test(s.body);
    if (!ok) {
      findings.push(finding(ctx, "WA-CFG-02", { title: "Keine security.txt vorhanden", category: "Information", kind: "informational", severity: "info", confidence: "high", url: stUrl, evidence: `GET ${stUrl} → Status ${s.status}`,
        description: "Eine security.txt (RFC 9116) teilt Sicherheitsforschenden mit, wie Schwachstellen gemeldet werden können.",
        remediation: "Datei /.well-known/security.txt mit mindestens «Contact:» und «Expires:» bereitstellen." }));
    }
    coverage.push({ checkId: "WA-CFG-02", state: "tested", method: "GET /.well-known/security.txt", evidence: `Status ${s.status}` });
  } catch (e) {
    coverage.push({ checkId: "WA-CFG-02", state: "error", limitation: (e as Error).message });
  }

  return { findings, coverage, pagesFetched: pages };
}
