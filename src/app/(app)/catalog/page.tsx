import { AUTOMATION_LABEL, CATALOG_VERSION, CHECKS, REFERENCES } from "@/lib/catalog";
import { MODE_LABEL } from "@/components/ui";

export default function CatalogPage() {
  return (
    <div className="space-y-4">
      <h1 className="h1">Prüfkatalog {CATALOG_VERSION} und Coverage-Matrix</h1>
      <section className="card">
        <h2 className="h2 mb-2">Referenzwerke</h2>
        <table className="table">
          <thead><tr><th>Referenz</th><th>Version</th><th>Übernommen</th><th>Lizenz / Nutzung</th></tr></thead>
          <tbody>
            {REFERENCES.map((r) => (
              <tr key={r.id}><td><b>{r.name}</b><div className="hint break-all">{r.source}</div></td><td>{r.version}</td><td>{r.adoptedAt}</td><td className="text-xs">{r.license}<div className="hint">{r.usage}</div></td></tr>
            ))}
          </tbody>
        </table>
      </section>
      <section className="card overflow-x-auto">
        <h2 className="h2 mb-2">Coverage-Matrix</h2>
        <p className="hint mb-2">Ob ein Prüfpunkt in einem konkreten Scan geprüft wurde, steht in der Abdeckung des jeweiligen Scans. Ein URL-Scan belegt keine ASVS-Level-Erfüllung und keine ISO- oder Datenschutzkonformität.</p>
        <table className="table">
          <thead><tr><th>ID</th><th>Anforderung/Test</th><th>Referenzen</th><th>Eingaben</th><th>Methode</th><th>Automatisierung</th><th>Implementiert</th><th>Modi</th><th>Einschränkungen</th></tr></thead>
          <tbody>
            {CHECKS.map((c) => (
              <tr key={c.id}>
                <td className="font-mono text-xs">{c.id}</td>
                <td>{c.title}</td>
                <td className="text-xs">{c.refs.map(([f, v, id, ver]) => <div key={f + id}>{f} {v} {id}{ver ? "" : " (unverifiziert)"}</div>)}</td>
                <td className="text-xs">{c.inputs.join(", ")}</td>
                <td className="text-xs">{c.method}</td>
                <td className="text-xs">{AUTOMATION_LABEL[c.automation]}</td>
                <td>{c.implemented ? "Ja" : "Nein"}</td>
                <td className="text-xs">{c.modes.map((m) => MODE_LABEL[m]?.split(" – ")[0]).join(", ") || "–"}</td>
                <td className="max-w-xs text-xs">{c.limitations}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </section>
    </div>
  );
}
