import { PDFDocument, StandardFonts, rgb, type PDFFont, type PDFPage } from "pdf-lib";
import type { ReportData } from "./data";
import { DISCLAIMER, METRICS_EXPLANATION } from "./data";
import { CATALOG_VERSION, REFERENCES, checkById, COVERAGE_LABEL } from "../catalog";
import { CONFIDENCE_LABEL, KIND_LABEL, SEVERITY_LABEL, STATUS_LABEL } from "../findings/types";
import { redact } from "../security/redact";

const MODE_LABEL = { baseline: "A – Schonender Basischeck", authenticated: "B – Authentifizierter Check", active: "C – Aktiver Check", repository: "D – Repository-Check" } as const;
const ENV_LABEL = { production: "Produktion", staging: "Staging", development: "Entwicklung" } as const;

class Writer {
  page!: PDFPage;
  y = 0;
  readonly margin = 50;
  readonly width = 595.28;
  readonly height = 841.89;
  private charset: Set<number>;
  constructor(
    private doc: PDFDocument,
    private font: PDFFont,
    private bold: PDFFont,
    private mono: PDFFont,
  ) {
    this.charset = new Set(font.getCharacterSet());
    this.newPage();
  }
  newPage() {
    this.page = this.doc.addPage([this.width, this.height]);
    this.y = this.height - this.margin;
    this.page.drawText(this.clean("WebAudit Security – vertraulich"), { x: this.margin, y: 20, size: 7, font: this.font, color: rgb(0.5, 0.5, 0.5) });
  }
  clean(s: string): string {
    const map: Record<string, string> = { "→": "->", "←": "<-", "≠": "!=", "≤": "<=", "≥": ">=", "✓": "OK", "✗": "X", "ˋ": "`", "\t": "  " };
    let out = "";
    for (const ch of s.normalize("NFC")) {
      if (map[ch]) out += map[ch];
      else if (ch === "\n" || this.charset.has(ch.codePointAt(0)!)) out += ch;
      else out += "?";
    }
    return out;
  }
  ensure(h: number) {
    if (this.y - h < this.margin) this.newPage();
  }
  text(s: string, o: { size?: number; bold?: boolean; mono?: boolean; color?: [number, number, number]; indent?: number; gap?: number } = {}) {
    const size = o.size ?? 10;
    const font = o.mono ? this.mono : o.bold ? this.bold : this.font;
    const maxW = this.width - 2 * this.margin - (o.indent ?? 0);
    for (const para of this.clean(s).split("\n")) {
      const words = para.split(/(\s+)/);
      let line = "";
      const flush = () => {
        this.ensure(size + 3);
        this.page.drawText(line, { x: this.margin + (o.indent ?? 0), y: this.y - size, size, font, color: rgb(...(o.color ?? [0.1, 0.1, 0.12])) });
        this.y -= size + 3;
        line = "";
      };
      for (const w of words) {
        // Sehr lange Wörter (URLs) hart umbrechen
        let word = w;
        while (font.widthOfTextAtSize(word, size) > maxW) {
          let cut = word.length;
          while (cut > 1 && font.widthOfTextAtSize(word.slice(0, cut), size) > maxW) cut--;
          if (line) flush();
          line = word.slice(0, cut);
          flush();
          word = word.slice(cut);
        }
        if (font.widthOfTextAtSize(line + word, size) > maxW && line.trim()) {
          flush();
          line = word.trimStart();
        } else line += word;
      }
      if (line.trim() || para === "") flush();
    }
    this.y -= o.gap ?? 2;
  }
  heading(s: string, level: 1 | 2 | 3 = 1) {
    const size = level === 1 ? 16 : level === 2 ? 13 : 11;
    this.ensure(size + 30);
    this.y -= level === 1 ? 10 : 6;
    this.text(s, { size, bold: true, color: [0.05, 0.2, 0.4], gap: 4 });
  }
  rule() {
    this.ensure(8);
    this.page.drawLine({ start: { x: this.margin, y: this.y }, end: { x: this.width - this.margin, y: this.y }, thickness: 0.5, color: rgb(0.8, 0.8, 0.8) });
    this.y -= 8;
  }
  kv(rows: [string, string][]) {
    for (const [k, v] of rows) {
      this.ensure(14);
      const yStart = this.y;
      this.page.drawText(this.clean(k), { x: this.margin, y: yStart - 9, size: 9, font: this.bold });
      this.text(v || "–", { size: 9, indent: 150 });
    }
  }
}

function fmt(d: Date | string | null | undefined): string {
  if (!d) return "–";
  const x = typeof d === "string" ? new Date(d) : d;
  return x.toLocaleString("de-CH", { timeZone: "Europe/Zurich", dateStyle: "medium", timeStyle: "short" });
}

export async function buildPdfReport(d: ReportData): Promise<Uint8Array> {
  const doc = await PDFDocument.create();
  doc.setTitle(`Sicherheitsbericht ${d.site.name}`);
  doc.setProducer("WebAudit Security");
  doc.setCreationDate(new Date());
  const w = new Writer(doc, await doc.embedFont(StandardFonts.Helvetica), await doc.embedFont(StandardFonts.HelveticaBold), await doc.embedFont(StandardFonts.Courier));

  w.text("Sicherheitsbericht", { size: 22, bold: true, color: [0.05, 0.2, 0.4] });
  w.text(d.site.name, { size: 14 });
  w.y -= 6;
  w.text(DISCLAIMER, { size: 9, color: [0.55, 0.1, 0.1], gap: 8 });
  w.rule();

  // 1. Management-Zusammenfassung
  w.heading("1. Management-Zusammenfassung");
  const open = d.findings.filter((f) => f.kind !== "informational");
  const crit = (d.counts.critical ?? 0) + (d.counts.high ?? 0);
  w.text(
    `Im Prüfmodus ${MODE_LABEL[d.scan.mode]} wurden ${open.length} Feststellungen dokumentiert: ${d.byKind.vulnerability} Sicherheitslücke(n), ${d.byKind.configuration} Konfigurationshinweis(e) und ${d.byKind.suspicion} Verdachtsfall/-fälle, die noch verifiziert werden müssen. ` +
      (crit > 0 ? `${crit} Feststellung(en) sind als hoch oder kritisch eingestuft und sollten priorisiert behandelt werden. ` : "Es wurden keine als hoch oder kritisch eingestuften Feststellungen erkannt. Das bedeutet nicht, dass die Website sicher ist. ") +
      `Von ${d.modeChecks.length} in diesem Modus implementierten Prüfpunkten wurden ${d.testedCount} tatsächlich geprüft. Nicht geprüfte Bereiche sind in Abschnitt 6 aufgeführt.`,
    { gap: 6 },
  );
  w.kv(SEVERITY_ORDER_LABELS.map(([k, l]) => [l, String(d.counts[k] ?? 0)] as [string, string]));
  w.text(METRICS_EXPLANATION, { size: 8, color: [0.4, 0.4, 0.4], gap: 6 });

  // 2. Ziel und Umfang
  w.heading("2. Ziel, Umfang und Prüfzeitpunkt");
  w.kv([
    ["Website", d.site.name],
    ["Basis-URL", d.site.baseUrl],
    ["Umgebung", ENV_LABEL[d.site.environment]],
    ["Verantwortlich", d.site.ownerName],
    ["Prüfmodus", MODE_LABEL[d.scan.mode]],
    ["Start / Ende", `${fmt(d.scan.startedAt)} / ${fmt(d.scan.finishedAt)}`],
    ["Freigegebene Hosts", d.scan.scopeSnapshot.hosts.join(", ")],
    ["Erlaubte Pfade", d.scan.scopeSnapshot.includePaths.join(", ")],
    ["Ausgeschlossene Pfade", d.scan.scopeSnapshot.excludePaths.join(", ") || "–"],
    ["Limits", `max. ${d.scan.limits.maxRequests} Anfragen, ${d.scan.limits.requestsPerSecond}/s, ${d.scan.limits.maxDurationMinutes} min, Tiefe ${d.scan.limits.maxDepth}`],
    ...(d.scan.commitSha ? [["Commit", d.scan.commitSha] as [string, string]] : []),
    ...(d.approval ? [["Aktive Freigabe", `${d.approval.profile}, ${fmt(d.approval.windowStart)} – ${fmt(d.approval.windowEnd)}, Schreibwirkungen: ${d.approval.allowWriteEffects ? "erlaubt" : "nicht erlaubt"}`] as [string, string]] : []),
  ]);

  // 3. Methoden
  w.heading("3. Freigegebene und tatsächlich ausgeführte Prüfmethoden");
  for (const m of d.scan.executedMethods) w.text(`• ${m}`, { size: 9 });
  if (d.scan.unavailableAdapters.length) {
    w.text("Nicht verfügbar:", { bold: true, size: 9 });
    for (const u of d.scan.unavailableAdapters) w.text(`• ${u.adapter}: ${u.reason}`, { size: 9 });
  }
  if (d.scan.egressStats) w.text(`Netzwerkschutz: ${d.scan.egressStats.allowed} Verbindungen erlaubt, ${d.scan.egressStats.blocked} ausserhalb des Scopes blockiert.`, { size: 9 });

  // 4. Feststellungen
  w.heading("4. Feststellungen nach Priorität");
  if (!d.findings.length) w.text("Keine Feststellungen dokumentiert. Das ist kein Nachweis der Sicherheit; siehe Abdeckung.");
  for (const [i, f] of d.findings.entries()) {
    w.ensure(80);
    w.heading(`4.${i + 1} ${f.title}`, 3);
    w.kv([
      ["Art", KIND_LABEL[f.kind]],
      ["Schweregrad / Vertrauen", `${SEVERITY_LABEL[f.severity]} / ${CONFIDENCE_LABEL[f.confidence]}`],
      ["Status", STATUS_LABEL[f.status]],
      ["Betroffen", f.affectedFile ? `${f.affectedFile}${f.affectedLine ? `:${f.affectedLine}` : ""}` : (f.affectedUrl ?? "–")],
      ["Weitere Fundstellen", f.otherUrls.length ? `${f.otherUrls.length} (z. B. ${f.otherUrls[0]})` : "–"],
      ["Werkzeug / Regel", `${f.tool} ${f.toolVersion ?? ""} / ${f.ruleId}`],
      ["Kontext", f.authContext],
      ["Referenzen", f.references.map((r) => `${r.framework} ${r.id}${r.verified ? "" : " (unverifiziert)"}`).join(", ") || (f.cweId ? `CWE-${f.cweId}` : "–")],
      ...(f.cvssVector ? [["CVSS", `${f.cvssVersion} ${f.cvssVector} – ${f.cvssRationale ?? ""}`] as [string, string]] : []),
      ...(f.retestResult ? [["Nachprüfung", f.retestResult] as [string, string]] : []),
    ]);
    w.text(f.description, { size: 9 });
    w.text("Massnahme:", { size: 9, bold: true });
    w.text(f.remediation, { size: 9 });
    w.text("Nachweis (bereinigt):", { size: 9, bold: true });
    w.text(redact(f.evidence, { maxLength: 900 }), { size: 7.5, mono: true, color: [0.25, 0.25, 0.25], gap: 6 });
  }

  // 5. Vergleich
  w.heading("5. Vergleich mit vorherigem Scan");
  if (!d.comparison) w.text("Kein vorheriger abgeschlossener Scan desselben Modus vorhanden.");
  else {
    w.kv([
      ["Vorheriger Scan", `${d.comparison.previousScanId.slice(0, 8)} vom ${fmt(d.comparison.previousDate)}`],
      ["Neu", String(d.comparison.newCount)],
      ["Behoben (nicht mehr gefunden, Prüfpunkt erneut geprüft)", String(d.comparison.resolved.length)],
      ["Unverändert", String(d.comparison.unchanged)],
      ["Nicht erneut geprüft", String(d.comparison.notRetested)],
    ]);
    for (const r of d.comparison.resolved.slice(0, 30)) w.text(`• ${r.title} – ${r.affected}`, { size: 8 });
  }

  // 6. Abdeckung
  w.heading("6. Prüfabdeckung und nicht geprüfte Bereiche");
  for (const c of d.coverage) {
    const chk = checkById(c.checkId);
    w.text(`${c.checkId} – ${chk?.title ?? ""}: ${COVERAGE_LABEL[c.state]}${c.limitation ? ` (${c.limitation})` : ""}`, { size: 8 });
  }
  w.text("Nicht Bestandteil dieses Prüfmodus bzw. nicht automatisiert:", { size: 9, bold: true });
  for (const c of d.notCovered) w.text(`• ${c.id} – ${c.title} (${c.implemented ? "anderer Modus" : "nicht implementiert / manuell"})`, { size: 8 });

  // 7. Werkzeuge und Referenzen
  w.heading("7. Verwendete Werkzeuge und Referenzversionen");
  w.kv(Object.entries(d.scan.toolVersions).map(([k, v]) => [k, v] as [string, string]));
  w.text(`Prüfkatalog-Version ${CATALOG_VERSION}`, { size: 9, bold: true });
  for (const r of REFERENCES) w.text(`• ${r.name} ${r.version} (übernommen ${r.adoptedAt}; ${r.license})`, { size: 8 });

  w.y -= 10;
  w.rule();
  w.text(DISCLAIMER, { size: 8, color: [0.55, 0.1, 0.1] });

  return doc.save();
}

const SEVERITY_ORDER_LABELS = (["critical", "high", "medium", "low", "info"] as const).map((k) => [k, SEVERITY_LABEL[k]] as const);
