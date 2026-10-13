import Link from "next/link";
import { asc, desc, eq } from "drizzle-orm";
import { notFound } from "next/navigation";
import { getDb } from "@/lib/db";
import { coverageResults, findings, reports, scanEvents, sites } from "@/lib/db/schema";
import { requireUser } from "@/lib/auth/current";
import { requireScan } from "@/lib/auth/rbac";
import { cancelScanAction, createReportAction } from "@/app/actions/scans";
import { Alert, ConfidenceBadge, ENV_LABEL, ErrorFromQuery, KindBadge, MODE_LABEL, ScanStatusBadge, SeverityBadge, StatusBadge, fmtDate } from "@/components/ui";
import { ScanProgress } from "@/components/scan-progress";
import { SEVERITY_ORDER, KIND_LABEL, SEVERITY_LABEL, STATUS_LABEL, type FindingKind } from "@/lib/findings/types";
import { COVERAGE_LABEL, checkById, checksForMode } from "@/lib/catalog";
import { DISCLAIMER, METRICS_EXPLANATION } from "@/lib/reports/data";

type SP = { error?: string; ok?: string; severity?: string; kind?: string; status?: string; tool?: string; category?: string };

export default async function ScanPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<SP> }) {
  const { id } = await params;
  const sp = await searchParams;
  const user = await requireUser();
  const db = getDb();
  const scan = await requireScan(db, user.userId, id, "scan.read").catch(() => notFound());
  const [site] = await db.select().from(sites).where(eq(sites.id, scan.siteId));
  const all = await db.select().from(findings).where(eq(findings.scanId, scan.id));
  const cov = await db.select().from(coverageResults).where(eq(coverageResults.scanId, scan.id));
  const reps = await db.select().from(reports).where(eq(reports.scanId, scan.id)).orderBy(desc(reports.createdAt));
  const events = await db.select().from(scanEvents).where(eq(scanEvents.scanId, scan.id)).orderBy(asc(scanEvents.createdAt));
  const running = ["queued", "running", "cancel_requested"].includes(scan.status);

  const filtered = all
    .filter((f) => !sp.severity || f.severity === sp.severity)
    .filter((f) => !sp.kind || f.kind === sp.kind)
    .filter((f) => !sp.status || f.status === sp.status)
    .filter((f) => !sp.tool || f.tool === sp.tool)
    .filter((f) => !sp.category || f.category === sp.category)
    .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity));
  const groups: FindingKind[] = ["vulnerability", "configuration", "suspicion", "informational"];
  const modeChecks = checksForMode(scan.mode);
  const tested = cov.filter((c) => c.state === "tested").length;
  const nonInfo = all.filter((f) => f.kind !== "informational");
  const highCrit = nonInfo.filter((f) => f.severity === "high" || f.severity === "critical").length;
  const tools = [...new Set(all.map((f) => f.tool))];
  const categories = [...new Set(all.map((f) => f.category))];

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="h1">Scan {scan.id.slice(0, 8)} – {site?.name}</h1>
          <p className="text-sm text-slate-600">{MODE_LABEL[scan.mode]} · {ENV_LABEL[site!.environment]} · erstellt {fmtDate(scan.createdAt)} · <ScanStatusBadge s={scan.status} /></p>
        </div>
        <div className="flex gap-2">
          <Link className="btn-secondary" href={`/sites/${scan.siteId}`}>Zur Website</Link>
          {scan.previousScanId && scan.status === "completed" ? <Link className="btn-secondary" href={`/scans/${scan.id}/compare`}>Vergleich mit Vorscan</Link> : null}
          {running ? (
            <form action={cancelScanAction}>
              <input type="hidden" name="scanId" value={scan.id} />
              <button className="btn-danger" type="submit">Scan abbrechen</button>
            </form>
          ) : null}
        </div>
      </div>
      <ErrorFromQuery error={sp.error} ok={sp.ok} />

      {running ? (
        <section className="card">
          <h2 className="h2 mb-3">Fortschritt</h2>
          <ScanProgress scanId={scan.id} initial={{ status: scan.status, phase: scan.phase, progress: scan.progress, events: events.slice(-30).map((e) => ({ level: e.level, message: e.message, createdAt: e.createdAt.toISOString() })) }} />
        </section>
      ) : null}
      {scan.status === "failed" ? <Alert kind="error"><b>Scan fehlgeschlagen:</b> {scan.error}<br />Es wurden keine Ergebnisse erzeugt oder übernommen.</Alert> : null}
      {scan.status === "cancelled" ? <Alert kind="warn">Scan abgebrochen. Teilergebnisse wurden verworfen, damit nichts als «geprüft» erscheint.</Alert> : null}

      {scan.status === "completed" ? (
        <>
          <section className="card space-y-3">
            <h2 className="h2">Zusammenfassung für Verantwortliche</h2>
            <p className="text-sm">
              Im Modus «{MODE_LABEL[scan.mode]}» wurden <b>{nonInfo.length}</b> Feststellungen dokumentiert: {all.filter((f) => f.kind === "vulnerability").length} Sicherheitslücke(n), {all.filter((f) => f.kind === "configuration").length} Konfigurationshinweis(e), {all.filter((f) => f.kind === "suspicion").length} Verdachtsfall/-fälle (noch zu verifizieren).{" "}
              {highCrit ? <b className="text-red-700">{highCrit} davon sind hoch oder kritisch und sollten zuerst behandelt werden.</b> : "Keine Feststellung ist als hoch oder kritisch eingestuft – das ist keine Aussage, dass die Website sicher ist."}
            </p>
            <p className="text-sm">Prüfabdeckung: <b>{tested}</b> von {modeChecks.length} in diesem Modus implementierten Prüfpunkten wurden geprüft. Manuelle Prüfbereiche (z. B. Zugriffskontrolle, Business-Logik) sind nicht abgedeckt.</p>
            <p className="hint">{METRICS_EXPLANATION}</p>
            <p className="hint">{DISCLAIMER}</p>
          </section>

          <section className="card space-y-2 text-sm">
            <h2 className="h2">Technische Details</h2>
            <p>Gestartet {fmtDate(scan.startedAt)}, beendet {fmtDate(scan.finishedAt)}. {scan.commitSha ? <>Commit <code>{scan.commitSha}</code>.</> : null}</p>
            <p>Werkzeuge: {Object.entries(scan.toolVersions).map(([k, v]) => `${k} ${v}`).join(", ") || "–"}</p>
            <ul className="list-disc pl-5">{scan.executedMethods.map((m, i) => <li key={i}>{m}</li>)}</ul>
            {scan.unavailableAdapters.length ? <Alert kind="warn">Nicht verfügbar: {scan.unavailableAdapters.map((u) => `${u.adapter} (${u.reason})`).join("; ")}</Alert> : null}
            {scan.egressStats ? <p>Netzwerkschutz: {scan.egressStats.allowed} Verbindungen erlaubt, {scan.egressStats.blocked} blockiert{scan.egressStats.blockedSamples.length ? ` (z. B. ${scan.egressStats.blockedSamples[0]!.target}: ${scan.egressStats.blockedSamples[0]!.reason})` : ""}.</p> : null}
          </section>

          <section className="card space-y-3" id="berichte">
            <h2 className="h2">Berichte</h2>
            <div className="flex gap-2">
              {(["pdf", "json"] as const).map((f) => (
                <form key={f} action={createReportAction}>
                  <input type="hidden" name="scanId" value={scan.id} />
                  <input type="hidden" name="format" value={f} />
                  <button className="btn-secondary" type="submit">{f.toUpperCase()}-Bericht erzeugen</button>
                </form>
              ))}
            </div>
            {reps.length ? (
              <ul className="text-sm">
                {reps.map((r) => (
                  <li key={r.id}><a className="text-blue-800 underline" href={`/api/reports/${r.id}`}>{r.format.toUpperCase()} vom {fmtDate(r.createdAt)}</a> <span className="hint">({Math.round(r.sizeBytes / 1024)} KB, SHA-256 {r.sha256.slice(0, 12)}…)</span></li>
                ))}
              </ul>
            ) : null}
          </section>

          <section className="card space-y-3">
            <h2 className="h2">Feststellungen</h2>
            <form className="flex flex-wrap gap-2 text-sm" method="get">
              <select className="input w-auto" name="severity" defaultValue={sp.severity ?? ""}><option value="">Alle Schweregrade</option>{SEVERITY_ORDER.map((s) => <option key={s} value={s}>{SEVERITY_LABEL[s]}</option>)}</select>
              <select className="input w-auto" name="kind" defaultValue={sp.kind ?? ""}><option value="">Alle Arten</option>{groups.map((k) => <option key={k} value={k}>{KIND_LABEL[k]}</option>)}</select>
              <select className="input w-auto" name="status" defaultValue={sp.status ?? ""}><option value="">Alle Status</option>{Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
              <select className="input w-auto" name="tool" defaultValue={sp.tool ?? ""}><option value="">Alle Prüfmethoden</option>{tools.map((t) => <option key={t} value={t}>{t}</option>)}</select>
              <select className="input w-auto" name="category" defaultValue={sp.category ?? ""}><option value="">Alle Kategorien</option>{categories.map((t) => <option key={t} value={t}>{t}</option>)}</select>
              <button className="btn-secondary" type="submit">Filtern</button>
            </form>
            {groups.map((g) => {
              const items = filtered.filter((f) => f.kind === g);
              if (!items.length) return null;
              return (
                <div key={g} className="space-y-2">
                  <h3 className="mt-4 font-semibold">{KIND_LABEL[g]} ({items.length})</h3>
                  <table className="table">
                    <thead><tr><th>Schweregrad</th><th>Titel</th><th>Betroffen</th><th>Werkzeug</th><th>Kontext</th><th>Status</th></tr></thead>
                    <tbody>
                      {items.map((f) => (
                        <tr key={f.id}>
                          <td><SeverityBadge s={f.severity} /><div className="mt-1"><ConfidenceBadge c={f.confidence} /></div></td>
                          <td><Link className="text-blue-800 underline" href={`/findings/${f.id}`}>{f.title}</Link><div className="mt-1"><KindBadge k={f.kind} /> <span className="hint">{f.category}</span></div></td>
                          <td className="max-w-xs break-all text-xs">{f.affectedFile ? `${f.affectedFile}${f.affectedLine ? `:${f.affectedLine}` : ""}` : f.affectedUrl}{f.occurrences > 1 ? <div className="hint">+{f.occurrences - 1} weitere Fundstelle(n)</div> : null}</td>
                          <td className="text-xs">{f.tool}<div className="hint">{f.ruleId}</div></td>
                          <td className="text-xs">{f.authContext}</td>
                          <td><StatusBadge s={f.status} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              );
            })}
            {filtered.length === 0 ? <p className="text-sm text-slate-600">Keine Feststellungen für diese Filter.</p> : null}
          </section>

          <section className="card">
            <h2 className="h2 mb-3">Prüfabdeckung dieses Scans</h2>
            <table className="table">
              <thead><tr><th>Prüfpunkt</th><th>Status</th><th>Methode</th><th>Einschränkung / Nachweis</th></tr></thead>
              <tbody>
                {cov.sort((a, b) => a.checkId.localeCompare(b.checkId)).map((c) => (
                  <tr key={c.id}>
                    <td><b>{c.checkId}</b><div className="hint">{checkById(c.checkId)?.title}</div></td>
                    <td className={c.state === "tested" ? "text-green-700" : c.state === "error" ? "text-red-700" : "text-amber-700"}>{COVERAGE_LABEL[c.state]}</td>
                    <td className="text-xs">{c.method}</td>
                    <td className="max-w-md whitespace-pre-wrap break-all text-xs">{c.limitation ?? c.evidence}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </section>
        </>
      ) : null}
    </div>
  );
}
