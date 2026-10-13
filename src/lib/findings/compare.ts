export type ComparableFinding = { id: string; fingerprint: string; title: string; severity: string; kind: string; status: string; affectedUrl: string | null; affectedFile: string | null };

export type ScanComparison<T extends ComparableFinding> = {
  newFindings: T[];
  resolved: T[];
  unchanged: { current: T; previous: T }[];
  /** Feststellungen, deren Prüfbereich im aktuellen Scan nicht erneut geprüft wurde. */
  notRetested: T[];
};

/**
 * Vergleich zweier Scans derselben Website über Fingerprints.
 * «Behoben» gilt nur, wenn der zugehörige Prüfpunkt im aktuellen Scan tatsächlich geprüft
 * wurde (coverage = tested). Fehlt die Prüfung, wird die Feststellung als «nicht erneut
 * geprüft» ausgewiesen – nie stillschweigend als behoben.
 */
export function compareScans<T extends ComparableFinding & { checkId?: string | null; tool: string }>(
  previous: T[],
  current: T[],
  currentTestedChecks: Set<string>,
  currentTools: Set<string>,
): ScanComparison<T> {
  const curByFp = new Map(current.map((f) => [f.fingerprint, f]));
  const prevByFp = new Map(previous.map((f) => [f.fingerprint, f]));
  const result: ScanComparison<T> = { newFindings: [], resolved: [], unchanged: [], notRetested: [] };
  for (const f of current) {
    const p = prevByFp.get(f.fingerprint);
    if (p) result.unchanged.push({ current: f, previous: p });
    else result.newFindings.push(f);
  }
  for (const p of previous) {
    if (curByFp.has(p.fingerprint)) continue;
    const retested = p.checkId ? currentTestedChecks.has(p.checkId) : currentTools.has(p.tool);
    if (retested) result.resolved.push(p);
    else result.notRetested.push(p);
  }
  return result;
}
