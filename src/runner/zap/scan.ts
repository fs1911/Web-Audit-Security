import { ZapClient, type ZapAlert } from "./client";
import { startZap } from "./process";
import { zapAlertToFinding } from "./parse";
import { scopeToZapRegexes, type Scope } from "../../lib/security/scope";
import type { ScanLimits } from "../../lib/db/schema";
import type { RawFinding } from "../../lib/findings/types";

/**
 * Feste, überprüfbare Profile für aktive Prüfungen. Keine Regeln für DoS
 * (Buffer Overflow, Format String), keine Brute-Force-, keine OAST-/Cloud-Metadaten-Regeln.
 * Regeln mit möglicher Schreibwirkung (SQL-Injection-Varianten, persistentes XSS)
 * nur mit ausdrücklicher Freigabe «allowWriteEffects».
 */
export const ACTIVE_PROFILE_SAFE = [0, 6, 10045, 10058, 10095, 20019, 40003, 40008, 40012, 40028, 40029, 40032, 40035];
export const ACTIVE_PROFILE_WRITE_EFFECTS = [40014, 40016, 40017, 40018, 40019, 40020, 40021, 40022, 40024, 90019];

export type ZapScanOptions = {
  baseUrl: string;
  scope: Scope;
  limits: ScanLimits;
  allowedPorts: number[];
  egressProxyPort: number;
  authContext: string;
  /** Zusätzliche Header für authentifizierte Scans (über ZAP-Replacer gesetzt). */
  authHeaders?: { name: string; value: string }[];
  /** Zusätzliche Startpunkte (z. B. geschützte Prüf-URL einer Testrolle); müssen im Scope liegen. */
  seedUrls?: string[];
  active?: { allowWriteEffects: boolean };
  knownSecrets: string[];
  signal: AbortSignal;
  onProgress: (phase: string, pct: number, msg?: string) => void;
  log: (msg: string, level?: "info" | "warn" | "error") => void;
};

export type ZapScanResult = { findings: (RawFinding & { nativeCheck?: string })[]; urlsFound: number; version: string; activeRulesUsed: number[] };

async function sleep(ms: number, signal: AbortSignal) {
  await new Promise<void>((resolve) => {
    const t = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => {
      clearTimeout(t);
      resolve();
    }, { once: true });
  });
}

export async function runZapScan(o: ZapScanOptions): Promise<ZapScanResult> {
  o.onProgress("ZAP wird gestartet", 0);
  const zap = await startZap({ signal: o.signal });
  const api = new ZapClient(zap.baseUrl, zap.apiKey);
  const deadline = Date.now() + o.limits.maxDurationMinutes * 60_000;
  try {
    // --- Netzwerk: ausschliesslich über den Egress-Guard-Proxy ---
    await api.call("network", "action", "setHttpProxy", { host: "127.0.0.1", port: o.egressProxyPort, realm: "", username: "", password: "" });
    await api.call("network", "action", "setHttpProxyEnabled", { enabled: true });
    const proxyCheck = await api.call<{ getHttpProxy: { port: number } }>("network", "view", "getHttpProxy");
    const proxyOn = await api.call<{ isHttpProxyEnabled: string | boolean }>("network", "view", "isHttpProxyEnabled");
    if (Number(proxyCheck.getHttpProxy.port) !== o.egressProxyPort || String(proxyOn.isHttpProxyEnabled) !== "true") {
      throw new Error("ZAP-Upstream-Proxy konnte nicht verifiziert werden – Scan aus Sicherheitsgründen abgebrochen.");
    }
    try {
      for (const host of o.scope.hosts) {
        await api.call("network", "action", "addRateLimitRule", { description: `webaudit-${host}`, enabled: true, matchRegex: false, matchString: host, requestsPerSecond: o.limits.requestsPerSecond, groupBy: "rule" });
      }
    } catch (e) {
      o.log(`ZAP-Rate-Limit nicht gesetzt (${(e as Error).message}); Begrenzung erfolgt durch den Egress-Proxy.`, "warn");
    }
    await api.call("core", "action", "setOptionSingleCookieRequestHeader", { Boolean: true }).catch(() => undefined);

    // --- Authentifizierung (nur Header, über Replacer) ---
    for (const [i, h] of (o.authHeaders ?? []).entries()) {
      await api.call("replacer", "action", "addRule", { description: `webaudit-auth-${i}`, enabled: true, matchType: "REQ_HEADER", matchRegex: false, matchString: h.name, replacement: h.value, initiators: "" });
    }

    // --- Kontext / Scope ---
    const ctxName = "webaudit";
    const { contextId } = await api.call<{ contextId: string }>("context", "action", "newContext", { contextName: ctxName });
    const { include, exclude } = scopeToZapRegexes(o.scope, o.allowedPorts);
    for (const r of include) await api.call("context", "action", "includeInContext", { contextName: ctxName, regex: r });
    for (const r of exclude) {
      await api.call("context", "action", "excludeFromContext", { contextName: ctxName, regex: r });
      await api.call("spider", "action", "excludeFromScan", { regex: r });
    }

    // --- Spider: keine Formulare, Limits ---
    await api.call("spider", "action", "setOptionProcessForm", { Boolean: false });
    await api.call("spider", "action", "setOptionPostForm", { Boolean: false });
    await api.call("spider", "action", "setOptionMaxDepth", { Integer: o.limits.maxDepth });
    await api.call("spider", "action", "setOptionMaxChildren", { Integer: o.limits.maxChildren });
    await api.call("spider", "action", "setOptionThreadCount", { Integer: o.limits.threads });
    await api.call("spider", "action", "setOptionMaxDuration", { Integer: Math.max(1, Math.floor(o.limits.maxDurationMinutes / (o.active ? 3 : 2))) });
    // robots.txt-Disallow-Einträge NICHT als Linkquelle nutzen (dort stehen oft gerade die sensiblen Pfade)
    await api.call("spider", "action", "setOptionParseRobotsTxt", { Boolean: false });
    await api.call("spider", "action", "setOptionParseSitemapXml", { Boolean: true }).catch(() => undefined);
    await api.call("spider", "action", "setOptionSendRefererHeader", { Boolean: true }).catch(() => undefined);

    const results: string[] = [];
    const starts = [o.baseUrl, ...(o.seedUrls ?? [])];
    for (const [si, startUrl] of starts.entries()) {
      o.onProgress("Spider: Seiten im Scope erfassen", 5);
      const { scan: spiderId } = await api.call<{ scan: string }>("spider", "action", "scan", { url: startUrl, contextName: ctxName, recurse: true, subtreeOnly: false });
      for (;;) {
        if (o.signal.aborted) {
          await api.call("spider", "action", "stop", { scanId: spiderId }).catch(() => undefined);
          throw new Error("Abgebrochen");
        }
        if (Date.now() > deadline) {
          await api.call("spider", "action", "stop", { scanId: spiderId }).catch(() => undefined);
          o.log("Zeitlimit erreicht – Spider gestoppt.", "warn");
          break;
        }
        const { status } = await api.call<{ status: string }>("spider", "view", "status", { scanId: spiderId });
        const pct = (si * 100 + Number(status)) / starts.length;
        o.onProgress("Spider: Seiten im Scope erfassen", 5 + Math.round(pct * (o.active ? 0.25 : 0.5)));
        if (Number(status) >= 100) break;
        await sleep(2000, o.signal);
      }
      const r = await api.call<{ results: string[] }>("spider", "view", "results", { scanId: spiderId });
      for (const u of r.results) if (!results.includes(u)) results.push(u);
    }
    o.log(`Spider abgeschlossen: ${results.length} URLs im Scope erfasst.`);

    // --- Passive Analyse abwarten ---
    o.onProgress("Passive Analyse", o.active ? 32 : 58);
    for (;;) {
      if (o.signal.aborted) throw new Error("Abgebrochen");
      const { recordsToScan } = await api.call<{ recordsToScan: string }>("pscan", "view", "recordsToScan");
      if (Number(recordsToScan) === 0 || Date.now() > deadline) break;
      await sleep(1500, o.signal);
    }
    const passiveAlertIds = new Set((await fetchAlerts(api, o.baseUrl)).map((a) => a.id));

    // --- Aktive Prüfung (nur mit Freigabe) ---
    let activeRulesUsed: number[] = [];
    if (o.active) {
      o.onProgress("Aktive Prüfung (Profil webaudit-safe)", 35);
      const policy = "webaudit-safe";
      await api.call("ascan", "action", "addScanPolicy", { scanPolicyName: policy, alertThreshold: "MEDIUM", attackStrength: "LOW" });
      await api.call("ascan", "action", "disableAllScanners", { scanPolicyName: policy });
      const { scanners } = await api.call<{ scanners: { id: string }[] }>("ascan", "view", "scanners", { scanPolicyName: policy });
      const available = new Set(scanners.map((s) => Number(s.id)));
      const wanted = [...ACTIVE_PROFILE_SAFE, ...(o.active.allowWriteEffects ? ACTIVE_PROFILE_WRITE_EFFECTS : [])];
      activeRulesUsed = wanted.filter((id) => available.has(id));
      await api.call("ascan", "action", "enableScanners", { ids: activeRulesUsed.join(","), scanPolicyName: policy });
      await api.call("ascan", "action", "setOptionThreadPerHost", { Integer: Math.min(2, o.limits.threads) });
      await api.call("ascan", "action", "setOptionDelayInMs", { Integer: Math.ceil(1000 / o.limits.requestsPerSecond) });
      await api.call("ascan", "action", "setOptionMaxScanDurationInMins", { Integer: Math.max(1, Math.floor((deadline - Date.now()) / 60000)) });
      await api.call("ascan", "action", "setOptionMaxRuleDurationInMins", { Integer: 5 });
      await api.call("ascan", "action", "setOptionHandleAntiCSRFTokens", { Boolean: false }).catch(() => undefined);
      const { scan: ascanId } = await api.call<{ scan: string }>("ascan", "action", "scan", { url: o.baseUrl, recurse: true, inScopeOnly: false, scanPolicyName: policy, contextId });
      for (;;) {
        if (o.signal.aborted) {
          await api.call("ascan", "action", "stop", { scanId: ascanId }).catch(() => undefined);
          throw new Error("Abgebrochen");
        }
        if (Date.now() > deadline) {
          await api.call("ascan", "action", "stop", { scanId: ascanId }).catch(() => undefined);
          o.log("Zeitlimit erreicht – aktive Prüfung gestoppt.", "warn");
          break;
        }
        const { status } = await api.call<{ status: string }>("ascan", "view", "status", { scanId: ascanId });
        o.onProgress("Aktive Prüfung (Profil webaudit-safe)", 35 + Math.round(Number(status) * 0.5));
        if (Number(status) >= 100) break;
        await sleep(3000, o.signal);
      }
    }

    o.onProgress("Ergebnisse auswerten", 88);
    const alerts = await fetchAlerts(api, o.baseUrl);
    const findings = alerts
      .map((a) => zapAlertToFinding(a, { toolVersion: zap.version, authContext: o.authContext, origin: passiveAlertIds.has(a.id) ? "passive" : "active", knownSecrets: o.knownSecrets }))
      .filter((f): f is NonNullable<typeof f> => f !== null);
    return { findings, urlsFound: results.length, version: zap.version ?? "unbekannt", activeRulesUsed };
  } finally {
    await zap.stop();
  }
}

async function fetchAlerts(api: ZapClient, _baseUrl: string): Promise<ZapAlert[]> {
  // ZAP sieht ausschliesslich Verkehr, der den Egress-Proxy passiert hat (= Scope).
  const out: ZapAlert[] = [];
  for (let start = 0; ; start += 500) {
    const { alerts } = await api.call<{ alerts: ZapAlert[] }>("alert", "view", "alerts", { start, count: 500 });
    out.push(...alerts);
    if (alerts.length < 500) break;
  }
  return out;
}
