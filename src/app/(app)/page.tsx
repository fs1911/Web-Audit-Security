import Link from "next/link";
import { and, count, desc, eq, inArray, ne } from "drizzle-orm";
import { getDb } from "@/lib/db";
import { coverageResults, findings, scans, siteHosts, sites } from "@/lib/db/schema";
import { requireUserAndOrg } from "@/lib/auth/current";
import { ENV_LABEL, MODE_LABEL, ScanStatusBadge, SeverityBadge, fmtDate } from "@/components/ui";
import { SEVERITY_ORDER } from "@/lib/findings/types";

export default async function Dashboard() {
  const { org } = await requireUserAndOrg();
  const db = getDb();
  const siteRows = await db.select().from(sites).where(eq(sites.orgId, org.id)).orderBy(desc(sites.createdAt));
  const hostRows = siteRows.length ? await db.select().from(siteHosts).where(inArray(siteHosts.siteId, siteRows.map((s) => s.id))) : [];
  const recent = await db.select().from(scans).where(eq(scans.orgId, org.id)).orderBy(desc(scans.createdAt)).limit(15);

  // Offene Feststellungen: nur aus dem jeweils letzten abgeschlossenen Scan je Website und Modus
  const completed = await db.select().from(scans).where(and(eq(scans.orgId, org.id), eq(scans.status, "completed"))).orderBy(desc(scans.finishedAt));
  const latest = new Map<string, (typeof completed)[number]>();
  for (const s of completed) if (!latest.has(`${s.siteId}:${s.mode}`)) latest.set(`${s.siteId}:${s.mode}`, s);
  const latestIds = [...latest.values()].map((s) => s.id);
  const openBySev = latestIds.length
    ? await db
        .select({ severity: findings.severity, n: count() })
        .from(findings)
        .where(and(inArray(findings.scanId, latestIds), inArray(findings.status, ["open", "in_progress"]), ne(findings.kind, "informational")))
        .groupBy(findings.severity)
    : [];
  const cov = latestIds.length
    ? await db.select({ scanId: coverageResults.scanId, state: coverageResults.state, n: count() }).from(coverageResults).where(inArray(coverageResults.scanId, latestIds)).groupBy(coverageResults.scanId, coverageResults.state)
    : [];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <h1 className="h1">Dashboard</h1>
        <Link className="btn" href="/sites/new">Website hinzufügen</Link>
      </div>

      <div className="grid gap-4 md:grid-cols-2">
        <section className="card">
          <h2 className="h2 mb-3">Offene Feststellungen (letzter Scan je Website/Modus)</h2>
          <div className="flex flex-wrap gap-4">
            {SEVERITY_ORDER.map((s) => (
              <div key={s} className="text-center">
                <SeverityBadge s={s} />
                <div className="mt-1 text-2xl font-semibold">{openBySev.find((r) => r.severity === s)?.n ?? 0}</div>
              </div>
            ))}
          </div>
          <p className="hint mt-3">Befundzahlen sind kein Sicherheitsurteil. Null Befunde bedeutet nur: im geprüften Umfang nichts erkannt.</p>
        </section>
        <section className="card">
          <h2 className="h2 mb-3">Technische Prüfabdeckung (getrennt von Befunden)</h2>
          {latest.size === 0 ? (
            <p className="text-sm text-slate-600">Noch kein abgeschlossener Scan.</p>
          ) : (
            <table className="table">
              <thead><tr><th>Website</th><th>Modus</th><th>Geprüft</th><th>Nicht geprüft</th><th>Fehler</th></tr></thead>
              <tbody>
                {[...latest.values()].map((s) => {
                  const g = (st: string) => cov.find((c) => c.scanId === s.id && c.state === st)?.n ?? 0;
                  return (
                    <tr key={s.id}>
                      <td>{siteRows.find((x) => x.id === s.siteId)?.name}</td>
                      <td>{MODE_LABEL[s.mode]?.split(" – ")[0]}</td>
                      <td>{g("tested")}</td>
                      <td>{g("not_tested")}</td>
                      <td>{g("error")}</td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </section>
      </div>

      <section className="card">
        <h2 className="h2 mb-3">Hinterlegte Websites</h2>
        {siteRows.length === 0 ? (
          <p className="text-sm text-slate-600">Noch keine Website hinterlegt.</p>
        ) : (
          <table className="table">
            <thead><tr><th>Name</th><th>URL</th><th>Umgebung</th><th>Verifizierte Hosts</th><th></th></tr></thead>
            <tbody>
              {siteRows.map((s) => {
                const hs = hostRows.filter((h) => h.siteId === s.id);
                return (
                  <tr key={s.id}>
                    <td className="font-medium">{s.name}</td>
                    <td className="break-all">{s.baseUrl}</td>
                    <td>{ENV_LABEL[s.environment]}</td>
                    <td>{hs.filter((h) => h.verifiedAt).length} / {hs.length}</td>
                    <td><Link className="text-blue-800 underline" href={`/sites/${s.id}`}>Öffnen</Link></td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </section>

      <section className="card">
        <h2 className="h2 mb-3">Letzte Scans und Verlauf</h2>
        {recent.length === 0 ? (
          <p className="text-sm text-slate-600">Noch keine Scans.</p>
        ) : (
          <table className="table">
            <thead><tr><th>Erstellt</th><th>Website</th><th>Modus</th><th>Status</th><th>Phase</th><th></th></tr></thead>
            <tbody>
              {recent.map((s) => (
                <tr key={s.id}>
                  <td>{fmtDate(s.createdAt)}</td>
                  <td>{siteRows.find((x) => x.id === s.siteId)?.name}</td>
                  <td>{MODE_LABEL[s.mode]}</td>
                  <td><ScanStatusBadge s={s.status} /></td>
                  <td className="text-slate-600">{s.phase}</td>
                  <td className="space-x-2">
                    <Link className="text-blue-800 underline" href={`/scans/${s.id}`}>Details</Link>
                    {s.previousScanId && s.status === "completed" ? <Link className="text-blue-800 underline" href={`/scans/${s.id}/compare`}>Vergleich</Link> : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
