import type { ZapAlert } from "./client";
import type { Confidence, FindingKind, RawFinding, Severity } from "../../lib/findings/types";
import { redact } from "../../lib/security/redact";
import { refsForCheck } from "../../lib/catalog";

/**
 * Deutsche Texte für häufige ZAP-Regeln. Für alle anderen Regeln wird die englische
 * Originalbeschreibung von ZAP übernommen und als solche gekennzeichnet.
 * `nativeCheck`: Regel überschneidet sich mit einem eigenen Prüfpunkt; die Vorkommen
 * werden dort zusammengeführt.
 */
const RULES_DE: Record<string, { title: string; category: string; kind: FindingKind; description?: string; remediation?: string; nativeCheck?: string }> = {
  "10010": { title: "Cookie ohne HttpOnly-Attribut", category: "Cookies", kind: "configuration", nativeCheck: "WA-CK-02" },
  "10011": { title: "Cookie ohne Secure-Attribut", category: "Cookies", kind: "configuration", nativeCheck: "WA-CK-01" },
  "10054": { title: "Cookie ohne oder mit schwachem SameSite-Attribut", category: "Cookies", kind: "configuration", nativeCheck: "WA-CK-03" },
  "10020": { title: "Fehlender Schutz vor Clickjacking", category: "HTTP-Header", kind: "configuration", nativeCheck: "WA-HDR-05" },
  "10021": { title: "Header X-Content-Type-Options fehlt", category: "HTTP-Header", kind: "configuration", nativeCheck: "WA-HDR-03" },
  "10035": { title: "Strict-Transport-Security-Header fehlt oder ist schwach", category: "HTTP-Header", kind: "configuration", nativeCheck: "WA-HDR-01" },
  "10038": { title: "Content-Security-Policy-Header fehlt", category: "HTTP-Header", kind: "configuration", nativeCheck: "WA-HDR-02" },
  "10036": { title: "Server-Header gibt Versionsinformationen preis", category: "Informationspreisgabe", kind: "configuration", nativeCheck: "WA-HDR-06" },
  "10037": { title: "X-Powered-By-Header gibt Technologie preis", category: "Informationspreisgabe", kind: "configuration", nativeCheck: "WA-HDR-06" },
  "10055": {
    title: "Schwachstelle in der Content Security Policy",
    category: "HTTP-Header",
    kind: "configuration",
    description: "Die gesetzte Content Security Policy enthält Direktiven, die ihren Schutz abschwächen (z. B. 'unsafe-inline', Wildcards oder fehlende Direktiven ohne Fallback).",
    remediation: "Die Policy schrittweise verschärfen: Wildcards und 'unsafe-inline' entfernen, Nonces oder Hashes verwenden, object-src 'none' und base-uri 'none' setzen.",
  },
  "10063": {
    title: "Permissions-Policy-Header fehlt",
    category: "HTTP-Header",
    kind: "configuration",
    description: "Ohne Permissions-Policy können eingebettete Inhalte Browserfunktionen wie Kamera, Mikrofon oder Standort anfragen, sofern der Browser dies nicht anderweitig einschränkt.",
    remediation: "Einen Permissions-Policy-Header setzen, der nicht benötigte Funktionen deaktiviert, z. B. «camera=(), microphone=(), geolocation=()».",
  },
  "10015": {
    title: "Cache-Steuerung für möglicherweise sensible Inhalte",
    category: "HTTP-Header",
    kind: "configuration",
    description: "Antworten enthalten keine oder eine zu offene Cache-Steuerung. Sensible Inhalte könnten in gemeinsam genutzten Caches oder im Browser verbleiben.",
    remediation: "Für Seiten mit personenbezogenen oder sensiblen Inhalten «Cache-Control: no-store» setzen.",
  },
  "10027": {
    title: "Möglicherweise sensible Informationen in Kommentaren",
    category: "Informationspreisgabe",
    kind: "suspicion",
    description: "Im HTML- oder JavaScript-Quelltext wurden Kommentare mit Schlüsselwörtern gefunden, die auf interne Informationen hindeuten können.",
    remediation: "Kommentare prüfen und interne Hinweise vor der Auslieferung entfernen (z. B. per Build-Minifizierung).",
  },
  "10096": {
    title: "Zeitstempel in Antwort",
    category: "Informationspreisgabe",
    kind: "informational",
  },
  "10003": {
    title: "Möglicherweise verwundbare JavaScript-Bibliothek",
    category: "Abhängigkeiten",
    kind: "suspicion",
    description: "ZAP (Retire.js) hat anhand der Versionskennung eine JavaScript-Bibliothek mit bekannten Schwachstellen erkannt. Ob die verwundbare Funktion genutzt wird, ist nicht geprüft.",
    remediation: "Die Bibliothek auf eine unterstützte, nicht betroffene Version aktualisieren und die Nutzung prüfen.",
  },
  "10040": { title: "Gemischte Inhalte inkl. Skripte (HTTP auf HTTPS-Seite)", category: "Transportverschlüsselung", kind: "configuration", nativeCheck: "WA-MC-01" },
  "10098": {
    title: "Fehlkonfiguration bei Cross-Domain-Zugriffen (CORS)",
    category: "HTTP-Header",
    kind: "configuration",
    nativeCheck: "WA-HDR-07",
  },
  "10202": {
    title: "Formular ohne Anti-CSRF-Token",
    category: "Sitzungsverwaltung",
    kind: "suspicion",
    description: "Ein HTML-Formular enthält kein erkennbares Anti-CSRF-Token. Ob die Anwendung CSRF auf andere Weise verhindert (z. B. SameSite-Cookies, Origin-Prüfung), wurde nicht geprüft.",
    remediation: "Für zustandsändernde Formulare ein Anti-CSRF-Token oder eine gleichwertige Massnahme (SameSite=Strict/Lax, Origin-Prüfung) einsetzen.",
  },
  "90004": {
    title: "Unzureichende Site-Isolation gegen Spectre",
    category: "HTTP-Header",
    kind: "configuration",
    description: "Header wie Cross-Origin-Resource-Policy, Cross-Origin-Embedder-Policy oder Cross-Origin-Opener-Policy fehlen.",
    remediation: "Cross-Origin-Opener-Policy «same-origin» und, wo möglich, Cross-Origin-Resource-Policy setzen.",
    nativeCheck: "WA-HDR-08",
  },
  "10109": { title: "Moderne Webanwendung erkannt", category: "Information", kind: "informational" },
  "10049": { title: "Hinweise zur Cache-Speicherbarkeit", category: "Information", kind: "informational" },
  "10111": { title: "Authentifizierungsanfrage erkannt", category: "Information", kind: "informational" },
  "10112": { title: "Sitzungsverwaltung erkannt", category: "Information", kind: "informational" },
};

const RISK: Record<string, Severity> = { High: "high", Medium: "medium", Low: "low", Informational: "info" };
const CONF: Record<string, Confidence> = { Confirmed: "confirmed", High: "high", Medium: "medium", Low: "low" };

export function zapAlertToFinding(a: ZapAlert, ctx: { toolVersion?: string; authContext: string; origin: "passive" | "active"; knownSecrets: string[] }): (RawFinding & { nativeCheck?: string }) | null {
  if (a.confidence === "False Positive") return null;
  const de = RULES_DE[a.pluginId];
  const severity = RISK[a.risk] ?? "info";
  const confidence = CONF[a.confidence] ?? "low";
  let kind: FindingKind;
  if (severity === "info") kind = "informational";
  else if (de) kind = de.kind;
  else if (ctx.origin === "active" && (confidence === "high" || confidence === "confirmed" || confidence === "medium")) kind = "vulnerability";
  else kind = "suspicion";
  if (confidence === "low" && kind === "vulnerability") kind = "suspicion";

  const cwe = Number(a.cweid);
  const evidenceParts = [
    `${a.method} ${a.url}`,
    a.param ? `Parameter: ${a.param}` : "",
    a.attack ? `Angriffswert (ZAP): ${a.attack}` : "",
    a.evidence ? `Nachweis: ${a.evidence}` : "",
    a.otherinfo ? `Zusatzinformation: ${a.otherinfo}` : "",
  ].filter(Boolean);
  const checkId = de?.nativeCheck ?? (ctx.origin === "active" ? "WA-ACT-01" : "WA-ZAP-PASSIVE");
  return {
    title: de?.title ?? a.alert ?? a.name,
    category: de?.category ?? "Webanwendung",
    kind,
    severity,
    confidence,
    checkId,
    affectedUrl: a.url,
    parameter: a.param || undefined,
    method: a.method,
    tool: "OWASP ZAP",
    toolVersion: ctx.toolVersion,
    ruleId: `zap:${a.pluginId}`,
    authContext: ctx.authContext,
    evidence: redact(evidenceParts.join("\n"), { maxLength: 2000, knownSecrets: ctx.knownSecrets }),
    description: de?.description ?? `[Originaltext ZAP, Englisch] ${a.description}`,
    remediation: de?.remediation ?? (a.solution ? `[Originaltext ZAP, Englisch] ${a.solution}` : "Siehe Referenzen der ZAP-Regel."),
    impact: undefined,
    limitations:
      ctx.origin === "passive"
        ? "Passive Erkennung anhand beobachteter Antworten; keine Ausnutzung versucht."
        : "Durch aktive ZAP-Regel erkannt; Ergebnis manuell bestätigen, bevor Massnahmen priorisiert werden.",
    references: de?.nativeCheck ? refsForCheck(de.nativeCheck) : cwe > 0 ? [{ framework: "CWE", version: "aus ZAP", id: `CWE-${cwe}`, verified: true }] : [],
    externalLinks: (a.reference ?? "")
      .split(/\s+/)
      .filter((s) => /^https?:\/\//.test(s))
      .slice(0, 5),
    cweId: cwe > 0 ? cwe : undefined,
    nativeCheck: de?.nativeCheck,
  };
}
