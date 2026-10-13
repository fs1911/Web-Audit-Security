import { requireUserAndOrg } from "@/lib/auth/current";
import { updateSettingsAction } from "@/app/actions/scans";
import { Alert, ErrorFromQuery } from "@/components/ui";
import { aiAvailable, AI_MODEL } from "@/lib/ai/explain";

export default async function SettingsPage({ searchParams }: { searchParams: Promise<{ error?: string; ok?: string }> }) {
  const { error, ok } = await searchParams;
  const { org } = await requireUserAndOrg();
  return (
    <div className="max-w-3xl space-y-4">
      <h1 className="h1">Einstellungen – {org.name}</h1>
      <ErrorFromQuery error={error} ok={ok} />
      <form action={updateSettingsAction} className="card space-y-4">
        <fieldset className="space-y-2">
          <legend className="h2">Externe KI-Verarbeitung</legend>
          <Alert kind="info">
            Wenn aktiviert, können einzelne Feststellungen auf Anforderung an Anthropic ({AI_MODEL}) übermittelt werden, um eine verständliche Erklärung zu erhalten.
            Übermittelt werden nur bereinigte Felder (Titel, Beschreibung, Massnahme, gekürzter Nachweis ohne Zugangsdaten). Die KI startet keine Scans, hat keinen Netzwerk- oder Shell-Zugriff und ändert nichts.
            Status Schlüssel: {aiAvailable() ? "konfiguriert" : "nicht konfiguriert (ANTHROPIC_API_KEY fehlt)"}.
          </Alert>
          <label className="flex items-center gap-2 text-sm"><input type="checkbox" name="aiEnabled" defaultChecked={org.aiEnabled} disabled={org.role !== "owner"} /> Externe KI-Verarbeitung für diese Organisation erlauben</label>
        </fieldset>
        <div>
          <label className="label" htmlFor="retentionDays">Aufbewahrung von Scans, Feststellungen und Berichten (Tage)</label>
          <input className="input w-40" id="retentionDays" name="retentionDays" type="number" min={7} max={3650} defaultValue={org.retentionDays} disabled={org.role !== "owner"} />
          <p className="hint">Ältere Daten werden durch «npm run retention» (z. B. täglich per Cron) gelöscht.</p>
        </div>
        {org.role === "owner" ? <button className="btn" type="submit">Speichern</button> : <p className="hint">Nur Eigentümer/innen können diese Einstellungen ändern.</p>}
      </form>
    </div>
  );
}
