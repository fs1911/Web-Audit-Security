import { and, eq, gt, isNull } from "drizzle-orm";
import { notFound } from "next/navigation";
import { getDb } from "@/lib/db";
import { credentials, scanApprovals } from "@/lib/db/schema";
import { requireUser } from "@/lib/auth/current";
import { requireSite } from "@/lib/auth/rbac";
import { startScanAction } from "@/app/actions/scans";
import { verifiedScope } from "@/lib/scans/service";
import { DEFAULT_LIMITS, HARD_LIMITS } from "@/lib/jobs/spec";
import { Alert, ENV_LABEL, ErrorFromQuery, MODE_LABEL, fmtDate } from "@/components/ui";
import { checksForMode } from "@/lib/catalog";
import { DEFAULT_STATE_CHANGING_PATTERNS } from "@/lib/security/scope";

export default async function StartScanPage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ error?: string }> }) {
  const { id } = await params;
  const { error } = await searchParams;
  const user = await requireUser();
  const db = getDb();
  const site = await requireSite(db, user.userId, id, "scan.start").catch(() => notFound());
  const scope = await verifiedScope(db, site);
  const creds = await db.select({ id: credentials.id, label: credentials.label, kind: credentials.kind }).from(credentials).where(eq(credentials.siteId, site.id));
  const approvals = await db.select().from(scanApprovals).where(and(eq(scanApprovals.siteId, site.id), isNull(scanApprovals.revokedAt), gt(scanApprovals.windowEnd, new Date())));
  const activeEnabled = process.env.ENABLE_ACTIVE_SCANS === "true";

  return (
    <div className="max-w-4xl space-y-4">
      <h1 className="h1">Scan starten – {site.name}</h1>
      <ErrorFromQuery error={error} />
      <section className="card space-y-2 text-sm">
        <h2 className="h2">Prüfumfang (wird vor dem Start fixiert)</h2>
        <p>Ziel: <b>{site.baseUrl}</b> · Umgebung: <b>{ENV_LABEL[site.environment]}</b></p>
        <p>Verifizierte Hosts: {scope.hosts.length ? scope.hosts.map((h) => <code key={h} className="mr-2">{h}</code>) : <span className="text-red-700">keine – Scan nicht möglich</span>}</p>
        <p>Erlaubte Pfade: <code>{scope.includePaths.join(", ")}</code> · Ausschlüsse: <code>{scope.excludePaths.join(", ") || "–"}</code></p>
        <p>Nie verfolgt werden Links mit: <code>{DEFAULT_STATE_CHANGING_PATTERNS.join(", ")}</code>. Formulare werden nie abgesendet.</p>
        <p>Netzwerkschutz: nur öffentliche Adressen, DNS-Prüfung bei jedem Verbindungsaufbau, Weiterleitungen ausserhalb des Scopes werden blockiert.</p>
      </section>
      <form action={startScanAction} className="card space-y-4">
        <input type="hidden" name="siteId" value={site.id} />
        <fieldset className="space-y-2">
          <legend className="label">Prüfmodus</legend>
          {(["baseline", "authenticated", "active", "repository"] as const).map((m) => {
            const disabled = (m === "active" && (!activeEnabled || approvals.length === 0)) || (m === "repository" && !site.repoUrl) || (m === "authenticated" && !creds.some((c) => c.kind !== "github_token"));
            return (
              <label key={m} className={`flex items-start gap-2 rounded border p-3 text-sm ${disabled ? "opacity-50" : ""}`}>
                <input type="radio" name="mode" value={m} defaultChecked={m === "baseline"} disabled={disabled} className="mt-1" />
                <span>
                  <b>{MODE_LABEL[m]}</b> – {checksForMode(m).length} implementierte Prüfpunkte
                  {m === "baseline" ? <div className="hint">TLS, Weiterleitung, Header, Cookies, Mixed Content, ZAP-Spider ohne Formulare, passive ZAP-Regeln.</div> : null}
                  {m === "authenticated" ? <div className="hint">Wie A, je Testrolle getrennt; Sitzungs- und Logout-Prüfung. {creds.some((c) => c.kind !== "github_token") ? "" : "Benötigt einen hinterlegten Testzugang."}</div> : null}
                  {m === "active" ? <div className="hint">ZAP-Aktivprofil «webaudit-safe». {activeEnabled ? (approvals.length ? "Gültige Freigabe vorhanden." : "Benötigt eine gültige Freigabe (Website-Seite).") : "Auf dieser Installation deaktiviert (ENABLE_ACTIVE_SCANS)."}</div> : null}
                  {m === "repository" ? <div className="hint">gitleaks, osv-scanner, semgrep auf festem Commit. {site.repoUrl ? site.repoUrl : "Kein Repository hinterlegt."}</div> : null}
                </span>
              </label>
            );
          })}
        </fieldset>
        {creds.length ? (
          <fieldset>
            <legend className="label">Testzugänge / Token</legend>
            {creds.map((c) => (
              <label key={c.id} className="mr-4 inline-flex items-center gap-2 text-sm">
                <input type="checkbox" name="credentialIds" value={c.id} /> {c.label} ({c.kind === "github_token" ? "GitHub" : c.kind})
              </label>
            ))}
          </fieldset>
        ) : null}
        {approvals.length ? (
          <div>
            <label className="label" htmlFor="approvalId">Freigabe (nur Modus C)</label>
            <select className="input" id="approvalId" name="approvalId">
              <option value="">–</option>
              {approvals.map((a) => (
                <option key={a.id} value={a.id}>{fmtDate(a.windowStart)} – {fmtDate(a.windowEnd)} · {a.maxRequests} Anfr. · {a.requestsPerSecond}/s</option>
              ))}
            </select>
          </div>
        ) : null}
        <div className="grid gap-3 md:grid-cols-4">
          <div><label className="label">Max. Dauer (min)</label><input className="input" name="maxDurationMinutes" type="number" defaultValue={DEFAULT_LIMITS.maxDurationMinutes} min={1} max={HARD_LIMITS.maxDurationMinutes} /></div>
          <div><label className="label">Max. Anfragen</label><input className="input" name="maxRequests" type="number" defaultValue={DEFAULT_LIMITS.maxRequests} min={10} max={HARD_LIMITS.maxRequests} /></div>
          <div><label className="label">Anfragen/Sekunde</label><input className="input" name="requestsPerSecond" type="number" defaultValue={DEFAULT_LIMITS.requestsPerSecond} min={1} max={HARD_LIMITS.requestsPerSecond} /></div>
          <div><label className="label">Crawl-Tiefe</label><input className="input" name="maxDepth" type="number" defaultValue={DEFAULT_LIMITS.maxDepth} min={1} max={HARD_LIMITS.maxDepth} /></div>
        </div>
        <Alert kind="info">Passiv bedeutet nicht zugriffsfrei: Der Crawler ruft Seiten im Scope ab und erzeugt Last und Logeinträge auf dem Zielsystem.</Alert>
        <label className="flex items-start gap-2 text-sm">
          <input type="checkbox" name="confirmScope" className="mt-1" required /> Ich habe Prüfumfang, Modus und Limits geprüft und starte den Scan.
        </label>
        <button className="btn" type="submit" disabled={scope.hosts.length === 0 && !site.repoUrl}>Scan starten</button>
      </form>
    </div>
  );
}
