import Link from "next/link";
import { desc, eq } from "drizzle-orm";
import { notFound } from "next/navigation";
import { getDb } from "@/lib/db";
import { findingStatusHistory, organizations, sites } from "@/lib/db/schema";
import { requireUser } from "@/lib/auth/current";
import { requireFinding } from "@/lib/auth/rbac";
import { explainFindingAction, updateFindingAction } from "@/app/actions/scans";
import { Alert, ConfidenceBadge, ErrorFromQuery, KindBadge, SeverityBadge, StatusBadge, fmtDate } from "@/components/ui";
import { CopyButton } from "@/components/scan-progress";
import { buildRepairPrompt } from "@/lib/findings/repair-prompt";
import { STATUS_LABEL } from "@/lib/findings/types";
import { aiAvailable, AI_MODEL } from "@/lib/ai/explain";

export default async function FindingPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ error?: string; ok?: string }> }) {
  const { id } = await params;
  const { error, ok } = await searchParams;
  const user = await requireUser();
  const db = getDb();
  const f = await requireFinding(db, user.userId, id, "scan.read").catch(() => notFound());
  const [site] = await db.select().from(sites).where(eq(sites.id, f.siteId));
  const [org] = await db.select().from(organizations).where(eq(organizations.id, f.orgId));
  const history = await db.select().from(findingStatusHistory).where(eq(findingStatusHistory.findingId, f.id)).orderBy(desc(findingStatusHistory.createdAt));
  const prompt = buildRepairPrompt({ ...f, environment: site!.environment, siteName: site!.name });

  return (
    <div className="max-w-5xl space-y-4">
      <Link className="text-sm text-blue-800 underline" href={`/scans/${f.scanId}`}>← Zurück zum Scan</Link>
      <h1 className="h1">{f.title}</h1>
      <div className="flex flex-wrap gap-2"><SeverityBadge s={f.severity} /><ConfidenceBadge c={f.confidence} /><KindBadge k={f.kind} /><StatusBadge s={f.status} /></div>
      <ErrorFromQuery error={error} ok={ok} />
      {f.kind === "suspicion" ? <Alert kind="warn">Verdacht – Verifikation erforderlich. Diese Feststellung ist nicht bestätigt.</Alert> : null}

      <section className="card grid gap-2 text-sm md:grid-cols-2">
        <div><b>Website / Umgebung:</b> {site?.name} / {site?.environment}</div>
        <div><b>Kategorie:</b> {f.category}</div>
        <div className="break-all"><b>Betroffen:</b> {f.affectedFile ? `${f.affectedFile}${f.affectedLine ? `:${f.affectedLine}` : ""}` : f.affectedUrl}{f.parameter ? ` · Parameter ${f.parameter}` : ""}</div>
        <div><b>Kontext:</b> {f.authContext}</div>
        <div><b>Werkzeug:</b> {f.tool} {f.toolVersion} · Regel {f.ruleId}</div>
        <div><b>Erkannt:</b> {fmtDate(f.detectedAt)}</div>
        <div><b>Referenzen:</b> {f.references.map((r) => `${r.framework} ${r.version} ${r.id}${r.verified ? "" : " (unverifiziert)"}`).join(" · ") || "–"}</div>
        <div><b>CWE:</b> {f.cweId ? `CWE-${f.cweId}` : "–"} · <b>CVSS:</b> {f.cvssVector ? `${f.cvssVersion} ${f.cvssVector}` : "nicht bewertet (keine ausreichende Grundlage)"}</div>
        {f.retestResult ? <div className="md:col-span-2"><b>Nachprüfung:</b> {f.retestResult}</div> : null}
        {f.otherUrls.length ? <div className="md:col-span-2 break-all"><b>Weitere Fundstellen ({f.otherUrls.length}):</b> {f.otherUrls.slice(0, 10).join(", ")}</div> : null}
      </section>

      <section className="card space-y-2 text-sm">
        <h2 className="h2">Beschreibung</h2>
        <p>{f.description}</p>
        {f.impact ? <><h3 className="font-semibold">Auswirkung</h3><p>{f.impact}</p></> : null}
        {f.limitations ? <><h3 className="font-semibold">Voraussetzungen und Einschränkungen</h3><p>{f.limitations}</p></> : null}
        <h3 className="font-semibold">Massnahme</h3>
        <p>{f.remediation}</p>
        {f.externalLinks.length ? <><h3 className="font-semibold">Quellen des Werkzeugs</h3><ul className="list-disc pl-5">{f.externalLinks.map((l) => <li key={l} className="break-all">{l}</li>)}</ul></> : null}
      </section>

      <section className="card space-y-2">
        <h2 className="h2">Technischer Nachweis (bereinigt)</h2>
        <pre className="code">{f.evidence}</pre>
      </section>

      {prompt ? (
        <section className="card space-y-2">
          <div className="flex items-center justify-between"><h2 className="h2">Claude-Code-Reparaturprompt</h2><CopyButton text={prompt} label="Prompt kopieren" /></div>
          <p className="hint">Deterministisch aus der gespeicherten Feststellung erzeugt. Die Plattform verändert die geprüfte Website nie selbst.</p>
          <pre className="code max-h-96 overflow-auto">{prompt}</pre>
        </section>
      ) : null}

      <section className="card space-y-2 text-sm">
        <h2 className="h2">KI-Erklärung (optional)</h2>
        {f.aiExplanation ? (
          <div className="space-y-2">
            <p>{f.aiExplanation.summary}</p>
            <ol className="list-decimal pl-5">{f.aiExplanation.steps.map((s, i) => <li key={i}>{s}</li>)}</ol>
            <p className="hint">Erstellt mit {f.aiExplanation.model} am {fmtDate(f.aiExplanation.createdAt)}. KI-Texte können Fehler enthalten.</p>
          </div>
        ) : null}
        {org?.aiEnabled && aiAvailable() ? (
          <form action={explainFindingAction}>
            <input type="hidden" name="findingId" value={f.id} />
            <p className="hint mb-2">Übermittelt bereinigte Felder dieser Feststellung an Anthropic ({AI_MODEL}). Keine Zugangsdaten, keine vollständigen Antwortinhalte.</p>
            <button className="btn-secondary" type="submit">Erklärung anfordern</button>
          </form>
        ) : (
          <p className="text-slate-600">Externe KI ist {org?.aiEnabled ? "nicht konfiguriert (kein API-Schlüssel)" : "für diese Organisation deaktiviert"}. Scans, Berichte und Reparaturprompts funktionieren unabhängig davon.</p>
        )}
      </section>

      <section className="card space-y-3">
        <h2 className="h2">Bearbeitung</h2>
        <form action={updateFindingAction} className="grid gap-3 md:grid-cols-3">
          <input type="hidden" name="findingId" value={f.id} />
          <div><label className="label">Status</label><select className="input" name="status" defaultValue={f.status}>{Object.entries(STATUS_LABEL).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></div>
          <div><label className="label">Verantwortlich</label><input className="input" name="assignee" defaultValue={f.assignee ?? ""} /></div>
          <div><label className="label">Frist</label><input className="input" name="dueDate" type="date" defaultValue={f.dueDate ? f.dueDate.toISOString().slice(0, 10) : ""} /></div>
          <div className="md:col-span-3"><label className="label">Kommentar (Pflicht bei Fehlalarm/Risikoakzeptanz)</label><input className="input" name="comment" /></div>
          <div><button className="btn-secondary" type="submit">Speichern</button></div>
        </form>
        {history.length ? (
          <ul className="text-xs text-slate-600">{history.map((h) => <li key={h.id}>{fmtDate(h.createdAt)}: {h.fromStatus ? STATUS_LABEL[h.fromStatus] : "–"} → {STATUS_LABEL[h.toStatus]}{h.comment ? ` («${h.comment}»)` : ""}</li>)}</ul>
        ) : null}
      </section>
    </div>
  );
}
