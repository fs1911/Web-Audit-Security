import { NetguardError, normalizeHostname, validateUrl, type NetguardPolicy, loadPolicy } from "./netguard";

/**
 * Prüfumfang (Scope). Wird deterministisch ausserhalb jedes Sprachmodells durchgesetzt.
 *
 * - `hosts`: ausschliesslich einzeln verifizierte Hosts. Keine Wildcards, keine automatische
 *   Freigabe von Subdomains.
 * - `includePaths`: erlaubte Pfadpräfixe (Standard "/").
 * - `excludePaths`: ausgeschlossene Pfadpräfixe oder Regex (Präfix "re:").
 * - `stateChangingPatterns`: Standardausschlüsse für potentiell zustandsändernde Links.
 */
export type Scope = {
  hosts: string[];
  includePaths: string[];
  excludePaths: string[];
};

export const DEFAULT_STATE_CHANGING_PATTERNS = [
  "logout",
  "log-out",
  "signout",
  "sign-out",
  "abmelden",
  "delete",
  "remove",
  "destroy",
  "loeschen",
  "löschen",
  "unsubscribe",
  "reset",
  "cancel",
  "deactivate",
  "revoke",
  "purge",
];

export function normalizeScope(s: Scope): Scope {
  const hosts = [...new Set(s.hosts.map((h) => normalizeHostname(h.trim())).filter(Boolean))];
  for (const h of hosts) {
    if (h.includes("*")) throw new NetguardError("Wildcard-Hosts sind nicht erlaubt", "OUT_OF_SCOPE");
  }
  const includePaths = s.includePaths.length ? s.includePaths.map(normPath) : ["/"];
  const excludePaths = s.excludePaths.map((p) => (p.startsWith("re:") ? p : normPath(p)));
  for (const p of excludePaths) {
    if (p.startsWith("re:")) {
      try {
        new RegExp(p.slice(3));
      } catch {
        throw new NetguardError(`Ungültiger Ausschluss-Ausdruck: ${p}`, "OUT_OF_SCOPE");
      }
    }
  }
  return { hosts, includePaths, excludePaths };
}

function normPath(p: string): string {
  let x = p.trim();
  if (!x.startsWith("/")) x = "/" + x;
  return x;
}

export type ScopeDecision = { inScope: true } | { inScope: false; reason: string };

/** Pfad aus URL dekodiert und normalisiert (verhindert Umgehung via %2e%2e oder doppelte Slashes). */
function canonicalPath(url: URL): string {
  let p = url.pathname;
  try {
    p = decodeURIComponent(p);
  } catch {
    /* Pfad bleibt kodiert */
  }
  return p.replace(/\/{2,}/g, "/").toLowerCase();
}

export function checkScope(rawUrl: string, scope: Scope, policy: NetguardPolicy = loadPolicy(), opts: { stateChangingGuard?: boolean } = {}): ScopeDecision {
  let v;
  try {
    v = validateUrl(rawUrl, policy);
  } catch (e) {
    return { inScope: false, reason: (e as Error).message };
  }
  if (!scope.hosts.includes(v.hostname)) return { inScope: false, reason: `Host ${v.hostname} ist nicht freigegeben` };
  const path = canonicalPath(v.url);
  if (path.split("/").includes("..")) return { inScope: false, reason: "Pfad-Traversal im Pfad" };
  if (!scope.includePaths.some((pre) => path.startsWith(pre.toLowerCase()))) {
    return { inScope: false, reason: "Pfad liegt ausserhalb der freigegebenen Pfade" };
  }
  for (const ex of scope.excludePaths) {
    if (ex.startsWith("re:")) {
      if (new RegExp(ex.slice(3), "i").test(path + v.url.search)) return { inScope: false, reason: `Ausgeschlossen durch ${ex}` };
    } else if (path.startsWith(ex.toLowerCase())) {
      return { inScope: false, reason: `Ausgeschlossener Pfad ${ex}` };
    }
  }
  if (opts.stateChangingGuard !== false) {
    const target = (path + v.url.search).toLowerCase();
    const hit = DEFAULT_STATE_CHANGING_PATTERNS.find((w) => target.includes(w));
    if (hit) return { inScope: false, reason: `Potentiell zustandsändernder Link (${hit}) wird nicht verfolgt` };
  }
  return { inScope: true };
}

function escapeRegex(s: string): string {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

/** Regex-Listen für ZAP-Kontext (include/exclude). */
export function scopeToZapRegexes(scope: Scope, ports: number[]): { include: string[]; exclude: string[] } {
  const include: string[] = [];
  const exclude: string[] = [];
  const portPart = `(:(${ports.join("|")}))?`;
  for (const h of scope.hosts) {
    for (const p of scope.includePaths) {
      include.push(`^https?://${escapeRegex(h)}${portPart}${escapeRegex(p)}.*`);
    }
    for (const ex of scope.excludePaths) {
      if (ex.startsWith("re:")) exclude.push(`^https?://${escapeRegex(h)}${portPart}.*${ex.slice(3)}.*`);
      else exclude.push(`^https?://${escapeRegex(h)}${portPart}${escapeRegex(ex)}.*`);
    }
  }
  exclude.push(`(?i).*(${DEFAULT_STATE_CHANGING_PATTERNS.map(escapeRegex).join("|")}).*`);
  return { include, exclude };
}
