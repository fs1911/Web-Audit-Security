import Link from "next/link";
import { and, eq } from "drizzle-orm";
import { notFound } from "next/navigation";
import { getDb } from "@/lib/db";
import { coverageResults, findings, scans } from "@/lib/db/schema";
import { requireUser } from "@/lib/auth/current";
import { requireScan } from "@/lib/auth/rbac";
import { compareScans } from "@/lib/findings/compare";
import { SeverityBadge, fmtDate } from "@/components/ui";

export default async function ComparePage({ params }: { params: Promise<{ id: string }> }) {
  const { id } = await params;
  const user = await requireUser();
  const db = getDb();
  const scan = await requireScan(db, user.userId, id, "scan.read").catch(() => notFound());
  if (!scan.previousScanId) notFound();
  // Vorscan muss zur selben Organisation gehören (Mandantentrennung)
  const [prevScan] = await db.select().from(scans).where(and(eq(scans.id, scan.previousScanId), eq(scans.orgId, scan.orgId)));
  if (!prevScan) notFound();
  const cur = await db.select().from(findings).where(eq(findings.scanId, scan.id));
  const prev = await db.select().from(findings).where(eq(findings.scanId, prevScan.id));
  const tested = new Set((await db.select().from(coverageResults).where(and(eq(coverageResults.scanId, scan.id), eq(coverageResults.state, "tested")))).map((c) => c.checkId));
  const cmp = compareScans(prev, cur, tested, new Set(Object.keys(scan.toolVersions)));

  const List = ({ title, items, note }: { title: string; items: typeof cur; note?: string }) => (
    <section className="card">
      <h2 className="h2 mb-2">{title} ({items.length})</h2>
      {note ? <p className="hint mb-2">{note}</p> : null}
      <ul className="space-y-1 text-sm">
        {items.map((f) => (
          <li key={f.id}><SeverityBadge s={f.severity} /> <Link className="text-blue-800 underline" href={`/findings/${f.id}`}>{f.title}</Link> <span className="hint break-all">{f.affectedUrl ?? f.affectedFile}</span></li>
        ))}
      </ul>
    </section>
  );

  return (
    <div className="space-y-4">
      <h1 className="h1">Vergleich</h1>
      <p className="text-sm text-slate-600">
        Aktueller Scan <Link className="underline" href={`/scans/${scan.id}`}>{scan.id.slice(0, 8)}</Link> ({fmtDate(scan.finishedAt)}) gegenüber <Link className="underline" href={`/scans/${prevScan.id}`}>{prevScan.id.slice(0, 8)}</Link> ({fmtDate(prevScan.finishedAt)}). Zuordnung über Fingerprints (Werkzeug, Regel, normalisierte Fundstelle, Parameter, Kontext).
      </p>
      <List title="Neu" items={cmp.newFindings} />
      <List title="Nicht mehr gefunden (Prüfpunkt erneut geprüft)" items={cmp.resolved} note="Gilt als behoben im geprüften Umfang. Ein nicht gefundener Befund ist kein Beweis für die vollständige Behebung." />
      <List title="Unverändert" items={cmp.unchanged.map((u) => u.current)} />
      <List title="Nicht erneut geprüft" items={cmp.notRetested} note="Der zugehörige Prüfpunkt wurde im aktuellen Scan nicht ausgeführt – Status unbekannt." />
    </div>
  );
}
