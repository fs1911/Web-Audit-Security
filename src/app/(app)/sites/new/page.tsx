import { createSiteAction } from "@/app/actions/sites";
import { Alert, ErrorFromQuery } from "@/components/ui";

export default async function NewSitePage({ searchParams }: { searchParams: Promise<{ error?: string }> }) {
  const { error } = await searchParams;
  return (
    <div className="max-w-3xl space-y-4">
      <h1 className="h1">Website hinzufügen</h1>
      <ErrorFromQuery error={error} />
      <Alert kind="info">
        Nach dem Anlegen muss jeder Host technisch verifiziert werden (DNS-TXT oder Challenge-Datei). Subdomains werden nie automatisch freigegeben.
        Testzugänge, Freigaben für aktive Prüfungen und GitHub-Token werden auf der Detailseite erfasst.
      </Alert>
      <form action={createSiteAction} className="card space-y-4">
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <label className="label" htmlFor="name">Name</label>
            <input className="input" id="name" name="name" required maxLength={120} />
          </div>
          <div>
            <label className="label" htmlFor="baseUrl">URL</label>
            <input className="input" id="baseUrl" name="baseUrl" type="url" placeholder="https://www.beispiel.ch/" required />
            <p className="hint">Nur http/https, Ports 80/443, keine Zugangsdaten in der URL.</p>
          </div>
          <div>
            <label className="label" htmlFor="environment">Umgebung</label>
            <select className="input" id="environment" name="environment" defaultValue="staging">
              <option value="production">Produktion</option>
              <option value="staging">Staging</option>
              <option value="development">Entwicklung</option>
            </select>
          </div>
          <div>
            <label className="label" htmlFor="ownerName">Eigentümer/verantwortliche Person</label>
            <input className="input" id="ownerName" name="ownerName" required maxLength={120} />
          </div>
        </div>
        <div>
          <label className="label" htmlFor="extraHosts">Weitere erlaubte Hosts (optional, je Zeile einer)</label>
          <textarea className="input" id="extraHosts" name="extraHosts" rows={2} placeholder="api.beispiel.ch" />
          <p className="hint">Jeder Host wird separat verifiziert. Keine Wildcards.</p>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <label className="label" htmlFor="includePaths">Erlaubte Pfade (je Zeile)</label>
            <textarea className="input" id="includePaths" name="includePaths" rows={3} defaultValue="/" />
          </div>
          <div>
            <label className="label" htmlFor="excludePaths">Ausgeschlossene Pfade (je Zeile; Regex mit «re:»)</label>
            <textarea className="input" id="excludePaths" name="excludePaths" rows={3} placeholder={"/admin\n/checkout\nre:.*\\.pdf$"} />
            <p className="hint">Zusätzlich werden Links mit logout, delete, remove, reset u. Ä. nie verfolgt.</p>
          </div>
        </div>
        <div className="grid gap-4 md:grid-cols-2">
          <div>
            <label className="label" htmlFor="apiSpecUrl">API-Spezifikation (optional, URL)</label>
            <input className="input" id="apiSpecUrl" name="apiSpecUrl" type="url" />
            <p className="hint">Wird gespeichert; ein API-Scan auf Basis der Spezifikation ist noch nicht implementiert.</p>
          </div>
          <div>
            <label className="label" htmlFor="repoUrl">GitHub-Repository (optional)</label>
            <input className="input" id="repoUrl" name="repoUrl" placeholder="https://github.com/org/repo" />
          </div>
        </div>
        <fieldset className="space-y-3 rounded-md border border-amber-300 bg-amber-50 p-4">
          <legend className="px-1 text-sm font-semibold text-amber-900">Prüfberechtigung</legend>
          <div>
            <label className="label" htmlFor="authorizationStatement">Grundlage der Berechtigung</label>
            <textarea className="input" id="authorizationStatement" name="authorizationStatement" rows={2} required placeholder="Eigene Website; ich bin Betreiber/in bzw. vom Betreiber schriftlich beauftragt (Auftrag vom …)." />
          </div>
          <label className="flex items-start gap-2 text-sm">
            <input type="checkbox" name="authorized" className="mt-1" required />
            <span>Ich bestätige, dass ich berechtigt bin, diese Website und alle angegebenen Hosts im angegebenen Umfang technisch prüfen zu lassen. Die Bestätigung wird mit meinem Namen und Zeitstempel im Audit-Log gespeichert.</span>
          </label>
        </fieldset>
        <button className="btn" type="submit">Website anlegen</button>
      </form>
    </div>
  );
}
