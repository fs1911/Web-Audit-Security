// Erzeugt docs/coverage-matrix.md aus dem versionierten Prüfkatalog.
import fs from "node:fs";
import { AUTOMATION_LABEL, CATALOG_VERSION, CHECKS, REFERENCES } from "../src/lib/catalog";

const modes: Record<string, string> = { baseline: "A", authenticated: "B", active: "C", repository: "D" };
const esc = (s: string) => s.replace(/\|/g, "\\|").replace(/\n/g, " ");
let md = `# Coverage-Matrix (Prüfkatalog ${CATALOG_VERSION})\n\n> Automatisch erzeugt mit \`npm run catalog:matrix\` aus \`catalog/checks.json\`. Nicht von Hand bearbeiten.\n>\n> «Geprüft / nicht geprüft / nicht anwendbar» und der **Nachweis** sind Eigenschaften eines konkreten Scans und stehen in der Abdeckung jedes Scans (UI, PDF- und JSON-Bericht). Diese Matrix beschreibt, was die Plattform prüfen *kann*.\n>\n> Ein URL-Scan belegt **keine** vollständige ASVS-Level-Erfüllung, keine ISO-Konformität und keine Datenschutzkonformität.\n\n## Referenzwerke\n\n| Referenz | Version | Quelle | Übernommen | Lizenz |\n|---|---|---|---|---|\n`;
for (const r of REFERENCES) md += `| ${esc(r.name)} | ${r.version} | ${r.source} | ${r.adoptedAt} | ${esc(r.license)} |\n`;
md += `\n## Prüfpunkte\n\n| ID | Anforderung/Test | Referenz und Version | Benötigte Eingaben | Prüfmethode | Automatisierung | Implementiert | Modi | Einschränkungen |\n|---|---|---|---|---|---|---|---|---|\n`;
for (const c of CHECKS) {
  const refs = c.refs.map(([f, v, id, ok]) => `${f} ${v} ${id}${ok ? "" : " (unverifiziert)"}`).join("<br>") || "–";
  md += `| ${c.id} | ${esc(c.title)} | ${refs} | ${esc(c.inputs.join(", "))} | ${c.method} | ${AUTOMATION_LABEL[c.automation]} | ${c.implemented ? "ja" : "nein"} | ${c.modes.map((m) => modes[m]).join(", ") || "–"} | ${esc(c.limitations) || "–"} |\n`;
}
fs.writeFileSync("docs/coverage-matrix.md", md);
console.log("docs/coverage-matrix.md geschrieben");
