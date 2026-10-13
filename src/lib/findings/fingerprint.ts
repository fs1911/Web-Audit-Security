import crypto from "node:crypto";
import type { RawFinding } from "./types";

/**
 * Normalisiert URLs für den Vergleich zwischen Scans: Query-Werte werden entfernt
 * (nur Parameternamen bleiben, sortiert), Fragment entfernt, Pfad kleingeschrieben,
 * numerische/UUID-Pfadsegmente generalisiert.
 */
export function normalizeUrlForFingerprint(raw: string | undefined): string {
  if (!raw) return "";
  try {
    const u = new URL(raw);
    const params = [...new Set([...u.searchParams.keys()])].sort();
    const path = u.pathname
      .toLowerCase()
      .split("/")
      .map((seg) => (/^\d+$/.test(seg) ? ":n" : /^[0-9a-f-]{32,36}$/i.test(seg) ? ":id" : seg))
      .join("/");
    const port = u.port ? `:${u.port}` : "";
    return `${u.protocol}//${u.hostname}${port}${path}${params.length ? "?" + params.join("&") : ""}`;
  } catch {
    return raw.toLowerCase();
  }
}

export function fingerprint(f: Pick<RawFinding, "tool" | "ruleId" | "affectedUrl" | "affectedFile" | "affectedLine" | "parameter" | "authContext">): string {
  const parts = [
    f.tool,
    f.ruleId,
    f.authContext,
    normalizeUrlForFingerprint(f.affectedUrl),
    f.affectedFile ?? "",
    // Zeilennummern ändern sich bei jeder Bearbeitung; Fingerprint bewusst ohne Zeile
    (f.parameter ?? "").toLowerCase(),
  ];
  return crypto.createHash("sha256").update(parts.join("|")).digest("hex").slice(0, 32);
}

/**
 * Duplikaterkennung: Gleicher Fingerprint → eine Feststellung mit Vorkommenszahl.
 * Zusätzlich werden seitenübergreifende Header-Feststellungen derselben Regel zu einer
 * Feststellung pro Host gruppiert (z. B. fehlender Header auf 40 Seiten).
 */
export type DedupedFinding = RawFinding & { fingerprint: string; occurrences: number; otherUrls: string[] };

const SITEWIDE_CATEGORIES = new Set(["HTTP-Header", "Cookies", "Transportverschlüsselung", "Informationspreisgabe"]);

export function dedupeFindings(items: RawFinding[]): DedupedFinding[] {
  const byKey = new Map<string, DedupedFinding>();
  for (const f of items) {
    let key: string;
    let groupUrl = f.affectedUrl;
    if (SITEWIDE_CATEGORIES.has(f.category) && f.affectedUrl && !f.parameter) {
      try {
        const u = new URL(f.affectedUrl);
        groupUrl = `${u.protocol}//${u.host}/`;
      } catch {
        /* unverändert */
      }
    }
    key = fingerprint({ ...f, affectedUrl: groupUrl });
    const existing = byKey.get(key);
    if (existing) {
      existing.occurrences += 1;
      if (f.affectedUrl && f.affectedUrl !== existing.affectedUrl && existing.otherUrls.length < 25 && !existing.otherUrls.includes(f.affectedUrl)) {
        existing.otherUrls.push(f.affectedUrl);
      }
      // Höhere Konfidenz gewinnt
      const rank = { confirmed: 4, high: 3, medium: 2, low: 1 } as const;
      if (rank[f.confidence] > rank[existing.confidence]) existing.confidence = f.confidence;
    } else {
      byKey.set(key, { ...f, fingerprint: key, occurrences: 1 + (f.otherUrls?.length ?? 0), otherUrls: [...(f.otherUrls ?? [])].slice(0, 25) });
    }
  }
  return [...byKey.values()];
}
