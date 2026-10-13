import Link from "next/link";
import { desc, eq } from "drizzle-orm";
import { notFound } from "next/navigation";
import { getDb } from "@/lib/db";
import { credentials, scanApprovals, scans, siteHosts } from "@/lib/db/schema";
import { requireUser } from "@/lib/auth/current";
import { requireSite } from "@/lib/auth/rbac";
import { addCredentialAction, addHostAction, createApprovalAction, deleteCredentialAction, revokeApprovalAction, verifyHostAction } from "@/app/actions/sites";
import { Alert, ENV_LABEL, ErrorFromQuery, MODE_LABEL, ScanStatusBadge, fmtDate } from "@/components/ui";
import { FILE_PATH, TXT_PREFIX } from "@/lib/verification";

export default async function SitePage({ params, searchParams }: { params: Promise<{ id: string }>; searchParams: Promise<{ error?: string; ok?: string }> }) {
  const { id } = await params;
  const { error, ok } = await searchParams;
  const user = await requireUser();
  const db = getDb();
  const site = await requireSite(db, user.userId, id, "site.read").catch(() => notFound());
  const hosts = await db.select().from(siteHosts).where(eq(siteHosts.siteId, site.id));
  const creds = await db.select({ id: credentials.id, label: credentials.label, kind: credentials.kind, headerName: credentials.headerName, verifyUrl: credentials.verifyUrl, logoutUrl: credentials.logoutUrl, createdAt: credentials.createdAt }).from(credentials).where(eq(credentials.siteId, site.id));
  const approvals = await db.select().from(scanApprovals).where(eq(scanApprovals.siteId, site.id)).orderBy(desc(scanApprovals.createdAt));
  const siteScans = await db.select().from(scans).where(eq(scans.siteId, site.id)).orderBy(desc(scans.createdAt)).limit(20);

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <h1 className="h1">{site.name}</h1>
          <p className="text-sm text-slate-600">{site.baseUrl} · {ENV_LABEL[site.environment]} · verantwortlich: {site.ownerName}</p>
        </div>
        <Link className="btn" href={`/sites/${site.id}/scan`}>Scan starten</Link>
      </div>
      <ErrorFromQuery error={error} ok={ok} />

      <section className="card space-y-3">
        <h2 className="h2">Scope</h2>
        <p className="text-sm">Erlaubte Pfade: <code>{site.includePaths.join(", ")}</code> · Ausgeschlossen: <code>{site.excludePaths.join(", ") || "–"}</code></p>
        <p className="text-sm">Prüfberechtigung bestätigt am {fmtDate(site.authorizationConfirmedAt)}: «{site.authorizationStatement}»</p>
        {site.repoUrl ? <p className="text-sm">Repository: {site.repoUrl}</p> : null}
        {site.apiSpecUrl ? <p className="text-sm">API-Spezifikation: {site.apiSpecUrl} (gespeichert, noch nicht ausgewertet)</p> : null}
      </section>

      <section className="card space-y-4">
        <h2 className="h2">Hosts und Domainverifikation</h2>
        <p className="text-sm text-slate-600">Nur verifizierte Hosts werden geprüft. Wählen Sie pro Host eine Methode:</p>
        <table className="table">
          <thead><tr><th>Host</th><th>Status</th><th>Nachweis</th><th>Verifizieren</th></tr></thead>
          <tbody>
            {hosts.map((h) => (
              <tr key={h.id}>
                <td className="font-mono">{h.host}</td>
                <td>{h.verifiedAt ? <span className="text-green-700">Verifiziert ({h.verificationMethod === "dns_txt" ? "DNS" : "Datei"}, {fmtDate(h.verifiedAt)})</span> : <span className="text-amber-700">Nicht verifiziert</span>}{h.lastCheckResult ? <div className="hint">{h.lastCheckResult}</div> : null}</td>
                <td className="space-y-2 text-xs">
                  <div><b>DNS-TXT:</b> <code className="break-all">{TXT_PREFIX}.{h.host}</code> → <code className="break-all">webaudit-verification={h.verificationToken}</code></div>
                  <div><b>Datei:</b> <code>{FILE_PATH}</code> mit Inhalt <code className="break-all">{h.verificationToken}</code></div>
                </td>
                <td className="space-y-1">
                  {(["dns_txt", "file"] as const).map((m) => (
                    <form key={m} action={verifyHostAction}>
                      <input type="hidden" name="siteId" value={site.id} />
                      <input type="hidden" name="hostId" value={h.id} />
                      <input type="hidden" name="method" value={m} />
                      <button className="btn-secondary w-full justify-center text-xs" type="submit">{m === "dns_txt" ? "DNS prüfen" : "Datei prüfen"}</button>
                    </form>
                  ))}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
        <form action={addHostAction} className="flex flex-wrap items-end gap-2">
          <input type="hidden" name="siteId" value={site.id} />
          <div className="grow">
            <label className="label" htmlFor="host">Weiteren Host hinzufügen</label>
            <input className="input" id="host" name="host" placeholder="api.beispiel.ch" required />
          </div>
          <button className="btn-secondary" type="submit">Hinzufügen</button>
        </form>
      </section>

      <section className="card space-y-4">
        <h2 className="h2">Testzugänge (für Modus B) und GitHub-Token (für Modus D)</h2>
        <Alert kind="warn">Nur separate Testkonten verwenden. Werte werden mit AES-256-GCM verschlüsselt gespeichert, nie angezeigt und in Logs/Berichten entfernt.</Alert>
        {creds.length ? (
          <table className="table">
            <thead><tr><th>Bezeichnung</th><th>Art</th><th>Prüf-URL</th><th>Logout-URL</th><th></th></tr></thead>
            <tbody>
              {creds.map((c) => (
                <tr key={c.id}>
                  <td>{c.label}</td>
                  <td>{c.kind === "header" ? `Header ${c.headerName}` : c.kind === "cookie" ? "Cookie" : "GitHub-Token"}</td>
                  <td className="break-all">{c.verifyUrl ?? "–"}</td>
                  <td className="break-all">{c.logoutUrl ?? "–"}</td>
                  <td>
                    <form action={deleteCredentialAction}>
                      <input type="hidden" name="siteId" value={site.id} />
                      <input type="hidden" name="credentialId" value={c.id} />
                      <button className="text-red-700 underline" type="submit">Löschen</button>
                    </form>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
        <form action={addCredentialAction} className="grid gap-3 md:grid-cols-3">
          <input type="hidden" name="siteId" value={site.id} />
          <div><label className="label">Bezeichnung / Testrolle</label><input className="input" name="label" placeholder="Redaktor (Testkonto)" required /></div>
          <div>
            <label className="label">Art</label>
            <select className="input" name="kind" defaultValue="header">
              <option value="header">HTTP-Header (z. B. Authorization)</option>
              <option value="cookie">Cookie-Header</option>
              <option value="github_token">GitHub-Token (nur Lesen)</option>
            </select>
          </div>
          <div><label className="label">Header-Name</label><input className="input" name="headerName" placeholder="Authorization" /></div>
          <div className="md:col-span-3"><label className="label">Wert</label><input className="input" name="value" type="password" autoComplete="off" required placeholder="Bearer … bzw. session=… bzw. github_pat_…" /></div>
          <div><label className="label">Prüf-URL (geschützte Seite)</label><input className="input" name="verifyUrl" type="url" /></div>
          <div><label className="label">Logout-URL (optional)</label><input className="input" name="logoutUrl" type="url" /></div>
          <div className="flex items-end"><button className="btn-secondary" type="submit">Zugang speichern</button></div>
        </form>
        <p className="hint">Formularbasierte Anmeldung mit Benutzername/Passwort ist noch nicht implementiert; hinterlegen Sie einen Sitzungs-Header bzw. ein Sitzungs-Cookie eines Testkontos.</p>
      </section>

      <section className="card space-y-4">
        <h2 className="h2">Freigaben für aktive Prüfungen (Modus C)</h2>
        <Alert kind="warn">
          Aktive Prüfungen senden Testangriffe. Standardempfehlung: nur Staging mit Testdaten. Ausgeschlossen sind DoS, Brute Force, Credential Stuffing und destruktive Tests.
          Regeln mit möglicher Schreibwirkung (z. B. SQL-Injection-Prüfungen, persistentes XSS) nur mit gesonderter Freigabe und nie auf Produktion.
        </Alert>
        {approvals.length ? (
          <table className="table">
            <thead><tr><th>Zeitfenster</th><th>Limits</th><th>Schreibwirkung</th><th>Begründung</th><th>Status</th></tr></thead>
            <tbody>
              {approvals.map((a) => (
                <tr key={a.id}>
                  <td>{fmtDate(a.windowStart)} – {fmtDate(a.windowEnd)}</td>
                  <td>{a.maxRequests} Anfr., {a.requestsPerSecond}/s</td>
                  <td>{a.allowWriteEffects ? "erlaubt" : "nein"}</td>
                  <td className="max-w-xs">{a.statement}</td>
                  <td>
                    {a.revokedAt ? "Widerrufen" : a.windowEnd < new Date() ? "Abgelaufen" : (
                      <form action={revokeApprovalAction}>
                        <input type="hidden" name="siteId" value={site.id} />
                        <input type="hidden" name="approvalId" value={a.id} />
                        <button className="text-red-700 underline" type="submit">Widerrufen</button>
                      </form>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ) : null}
        <form action={createApprovalAction} className="grid gap-3 md:grid-cols-3">
          <input type="hidden" name="siteId" value={site.id} />
          <div><label className="label">Beginn</label><input className="input" name="windowStart" type="datetime-local" required /></div>
          <div><label className="label">Ende</label><input className="input" name="windowEnd" type="datetime-local" required /></div>
          <div><label className="label">Profil</label><input className="input" value="webaudit-safe (fest)" disabled /></div>
          <div><label className="label">Max. Anfragen</label><input className="input" name="maxRequests" type="number" defaultValue={1000} min={10} max={5000} /></div>
          <div><label className="label">Anfragen/Sekunde</label><input className="input" name="requestsPerSecond" type="number" defaultValue={2} min={1} max={10} /></div>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" name="allowWriteEffects" disabled={site.environment === "production"} /> Regeln mit möglicher Schreibwirkung erlauben</label>
          <div className="md:col-span-3"><label className="label">Zweck, Testdaten, Ansprechperson</label><textarea className="input" name="statement" rows={2} required /></div>
          <label className="flex items-start gap-2 text-sm md:col-span-3"><input type="checkbox" name="confirmActive" className="mt-1" required /> Ich gebe aktive Prüfungen für dieses Ziel, diesen Umfang und dieses Zeitfenster ausdrücklich frei.</label>
          <div><button className="btn-secondary" type="submit">Freigabe erfassen</button></div>
        </form>
      </section>

      <section className="card">
        <h2 className="h2 mb-3">Scans dieser Website</h2>
        {siteScans.length === 0 ? <p className="text-sm text-slate-600">Noch keine Scans.</p> : (
          <table className="table">
            <thead><tr><th>Erstellt</th><th>Modus</th><th>Status</th><th></th></tr></thead>
            <tbody>
              {siteScans.map((s) => (
                <tr key={s.id}>
                  <td>{fmtDate(s.createdAt)}</td>
                  <td>{MODE_LABEL[s.mode]}</td>
                  <td><ScanStatusBadge s={s.status} /></td>
                  <td><Link className="text-blue-800 underline" href={`/scans/${s.id}`}>Details</Link></td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>
    </div>
  );
}
