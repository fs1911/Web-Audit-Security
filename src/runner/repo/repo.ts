import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { execFileSafe, which } from "../exec";
import type { CoverageEntry, RawFinding, Severity } from "../../lib/findings/types";
import { refsForCheck } from "../../lib/catalog";
import { redact } from "../../lib/security/redact";

/**
 * Repository-Prüfung (Modus D). Nur Lesezugriff: Klon eines festen Commits, keine
 * Änderungen, keine Commits. Unterstützt ausschliesslich https://github.com/<owner>/<repo>.
 */

export { parseGithubUrl } from "../../lib/github";
import { parseGithubUrl } from "../../lib/github";

type Adapter = { name: string; binary: string; checkId: string };
export const REPO_ADAPTERS: Adapter[] = [
  { name: "gitleaks", binary: "gitleaks", checkId: "WA-REPO-01" },
  { name: "osv-scanner", binary: "osv-scanner", checkId: "WA-REPO-02" },
  { name: "semgrep", binary: "semgrep", checkId: "WA-REPO-03" },
];

export async function repoAdapterAvailability(): Promise<{ name: string; available: boolean; reason?: string; path?: string }[]> {
  const out = [];
  for (const a of REPO_ADAPTERS) {
    const p = await which(a.binary);
    if (!p) out.push({ name: a.name, available: false, reason: `${a.binary} ist im Worker nicht installiert` });
    else if (a.name === "semgrep" && !semgrepRules()) out.push({ name: a.name, available: false, reason: "Kein Semgrep-Regelsatz konfiguriert (SEMGREP_RULES)" });
    else out.push({ name: a.name, available: true, path: p });
  }
  return out;
}

function semgrepRules(): string | null {
  const r = process.env.SEMGREP_RULES ?? path.resolve("rules/semgrep");
  return fs.existsSync(r) ? r : null;
}

type Ctx = { signal: AbortSignal; log: (m: string, l?: "info" | "warn" | "error") => void; knownSecrets: string[] };

export async function cloneRepo(url: string, token: string | undefined, ref: string | undefined, ctx: Ctx): Promise<{ dir: string; commit: string; cleanup: () => void }> {
  const gh = parseGithubUrl(url);
  if (!gh) throw new Error("Nur https://github.com/<owner>/<repo> wird unterstützt.");
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "webaudit-repo-"));
  const cleanup = () => fs.rmSync(dir, { recursive: true, force: true });
  const env: Record<string, string | undefined> = { PATH: process.env.PATH, HOME: dir, GIT_TERMINAL_PROMPT: "0", HTTPS_PROXY: process.env.HTTPS_PROXY, SSL_CERT_FILE: process.env.SSL_CERT_FILE, GIT_SSL_CAINFO: process.env.GIT_SSL_CAINFO };
  if (token) {
    // Token nur über Umgebungs-Konfiguration, nie in argv oder der Remote-URL.
    env.GIT_CONFIG_COUNT = "1";
    env.GIT_CONFIG_KEY_0 = "http.https://github.com/.extraheader";
    env.GIT_CONFIG_VALUE_0 = `Authorization: Basic ${Buffer.from(`x-access-token:${token}`).toString("base64")}`;
  }
  const cleanUrl = `https://github.com/${gh.owner}/${gh.repo}.git`;
  const target = path.join(dir, "src");
  const clone = await execFileSafe("git", ["clone", "--depth", "100", "--no-tags", "--single-branch", ...(ref && !/^[0-9a-f]{40}$/.test(ref) ? ["--branch", ref] : []), "--", cleanUrl, target], { env, timeoutMs: 5 * 60_000, signal: ctx.signal });
  if (clone.code !== 0) {
    cleanup();
    throw new Error(`Klonen fehlgeschlagen: ${redact(clone.stderr.slice(-400), { knownSecrets: ctx.knownSecrets })}`);
  }
  if (ref && /^[0-9a-f]{40}$/.test(ref)) {
    const fetch = await execFileSafe("git", ["-C", target, "fetch", "--depth", "100", "origin", ref], { env, timeoutMs: 120_000, signal: ctx.signal });
    const co = await execFileSafe("git", ["-C", target, "checkout", "--detach", ref], { env, timeoutMs: 60_000, signal: ctx.signal });
    if (fetch.code !== 0 || co.code !== 0) {
      cleanup();
      throw new Error("Angeforderter Commit konnte nicht ausgecheckt werden.");
    }
  }
  const head = await execFileSafe("git", ["-C", target, "rev-parse", "HEAD"], { env });
  return { dir: target, commit: head.stdout.trim(), cleanup };
}

function rel(root: string, p: string): string {
  return path.relative(root, p.startsWith("/") ? p : path.join(root, p)) || p;
}

export async function runGitleaks(dir: string, version: string, ctx: Ctx): Promise<RawFinding[]> {
  const report = path.join(os.tmpdir(), `gitleaks-${Date.now()}.json`);
  const r = await execFileSafe("gitleaks", ["git", dir, "--report-format", "json", "--report-path", report, "--redact", "--no-banner", "--exit-code", "0", "--log-level", "warn"], { signal: ctx.signal, timeoutMs: 10 * 60_000 });
  if (r.code !== 0) throw new Error(`gitleaks fehlgeschlagen: ${r.stderr.slice(-300)}`);
  const items = JSON.parse(fs.readFileSync(report, "utf8")) as { RuleID: string; Description: string; File: string; StartLine: number; Commit: string; Match: string; Secret: string; Author?: string; Email?: string }[];
  fs.rmSync(report, { force: true });
  return items.map((i) => ({
    title: `Mögliches Secret im Repository: ${i.Description || i.RuleID}`,
    category: "Secrets",
    kind: "suspicion" as const,
    severity: "high" as Severity,
    confidence: "medium" as const,
    checkId: "WA-REPO-01",
    affectedFile: rel(dir, i.File),
    affectedLine: i.StartLine,
    tool: "gitleaks",
    toolVersion: version,
    ruleId: `gitleaks:${i.RuleID}`,
    authContext: "repository",
    // gitleaks --redact ersetzt den Wert bereits; zusätzlich eigene Bereinigung
    evidence: redact(`Commit ${i.Commit.slice(0, 12)} · ${rel(dir, i.File)}:${i.StartLine}\nTreffer (geschwärzt): ${i.Match}`, { knownSecrets: [i.Secret, ...ctx.knownSecrets] }),
    description: "gitleaks hat ein Muster gefunden, das einem Zugangsschlüssel oder Passwort entspricht. Auch wenn die Datei inzwischen geändert wurde, bleibt das Secret in der Git-Historie abrufbar.",
    remediation: "Prüfen, ob es sich um ein echtes Secret handelt. Falls ja: Secret sofort beim Anbieter widerrufen/rotieren, aus dem Code entfernen und künftig über einen Secret-Manager bzw. Umgebungsvariablen beziehen. Die Historie zu bereinigen ersetzt die Rotation nicht.",
    limitations: "Musterbasierte Erkennung; Testdaten und Platzhalter können Fehlalarme sein.",
    references: refsForCheck("WA-REPO-01"),
    externalLinks: [],
    cweId: 798,
  }));
}

type OsvResult = { results?: { source: { path: string }; packages: { package: { name: string; version: string; ecosystem: string }; vulnerabilities?: { id: string; aliases?: string[]; summary?: string; details?: string; database_specific?: { severity?: string }; severity?: { type: string; score: string }[]; affected?: { ranges?: { events?: { fixed?: string }[] }[] }[] }[] }[] }[] };

const OSV_SEV: Record<string, Severity> = { CRITICAL: "critical", HIGH: "high", MODERATE: "medium", MEDIUM: "medium", LOW: "low" };

export async function runOsv(dir: string, version: string, ctx: Ctx): Promise<{ findings: RawFinding[]; lockfiles: number }> {
  const r = await execFileSafe("osv-scanner", ["scan", "source", "-r", "--format", "json", dir], { signal: ctx.signal, timeoutMs: 10 * 60_000, env: { PATH: process.env.PATH, HOME: os.tmpdir(), HTTPS_PROXY: process.env.HTTPS_PROXY, SSL_CERT_FILE: process.env.SSL_CERT_FILE } });
  // Exit 0 = keine Treffer, 1 = Treffer, 128 = keine Pakete gefunden
  if (r.code === 128) return { findings: [], lockfiles: 0 };
  if (r.code !== 0 && r.code !== 1) throw new Error(`osv-scanner fehlgeschlagen (Code ${r.code}): ${r.stderr.slice(-300)}`);
  const data = JSON.parse(r.stdout || "{}") as OsvResult;
  const findings: RawFinding[] = [];
  for (const res of data.results ?? []) {
    for (const pkg of res.packages) {
      for (const v of pkg.vulnerabilities ?? []) {
        const cve = [v.id, ...(v.aliases ?? [])].find((x) => x.startsWith("CVE-"));
        const sev = OSV_SEV[(v.database_specific?.severity ?? "").toUpperCase()] ?? "medium";
        const fixed = v.affected?.flatMap((a) => a.ranges?.flatMap((rg) => rg.events?.map((e) => e.fixed).filter(Boolean) ?? []) ?? []) ?? [];
        const cvss = v.severity?.find((s) => s.type.startsWith("CVSS_V"));
        findings.push({
          title: `${pkg.package.name}@${pkg.package.version}: ${v.summary ?? v.id}`,
          category: "Abhängigkeiten",
          kind: "vulnerability",
          severity: sev,
          confidence: "high",
          checkId: "WA-REPO-02",
          affectedFile: rel(dir, res.source.path),
          tool: "osv-scanner",
          toolVersion: version,
          ruleId: `osv:${v.id}`,
          authContext: "repository",
          evidence: `${rel(dir, res.source.path)}: ${pkg.package.ecosystem} ${pkg.package.name} ${pkg.package.version}\nOSV: ${v.id}${v.aliases?.length ? ` (Aliase: ${v.aliases.join(", ")})` : ""}`,
          description: `Die eingesetzte Version ist laut OSV-Datenbank von ${v.id}${cve && cve !== v.id ? ` / ${cve}` : ""} betroffen. ${redact(v.details ?? "", { maxLength: 600 })}`,
          remediation: fixed.length ? `Auf eine nicht betroffene Version aktualisieren (behoben in: ${[...new Set(fixed)].slice(0, 3).join(", ")}).` : "Prüfen, ob ein Update oder eine Abhilfe verfügbar ist; andernfalls Risiko bewerten.",
          limitations: "Ob die verwundbare Funktion tatsächlich erreichbar ist, wurde nicht geprüft.",
          references: [...refsForCheck("WA-REPO-02"), ...(cve ? [{ framework: "CVE", version: "OSV", id: cve, verified: true }] : [])],
          externalLinks: [`https://osv.dev/vulnerability/${encodeURIComponent(v.id)}`],
          cvss: cvss ? { version: cvss.type.replace("CVSS_V", ""), vector: cvss.score, score: "", rationale: "Vektor aus der OSV-Datenbank übernommen, nicht von der Plattform berechnet." } : undefined,
        });
      }
    }
  }
  return { findings, lockfiles: data.results?.length ?? 0 };
}

type SemgrepOut = { results: { check_id: string; path: string; start: { line: number }; extra: { message: string; severity: string; lines?: string; metadata?: { cwe?: string[] | string; confidence?: string } } }[]; errors: unknown[] };

export async function runSemgrep(dir: string, version: string, ctx: Ctx): Promise<RawFinding[]> {
  const rules = semgrepRules();
  if (!rules) throw new Error("Kein Semgrep-Regelsatz konfiguriert");
  const r = await execFileSafe("semgrep", ["scan", "--config", rules, "--json", "--metrics=off", "--disable-version-check", "--timeout", "30", "--max-target-bytes", "1000000", dir], {
    signal: ctx.signal,
    timeoutMs: 15 * 60_000,
    env: { PATH: process.env.PATH, HOME: os.tmpdir(), SEMGREP_SEND_METRICS: "off" },
  });
  if (r.code !== 0 && r.code !== 1) throw new Error(`semgrep fehlgeschlagen (Code ${r.code}): ${r.stderr.slice(-300)}`);
  const data = JSON.parse(r.stdout) as SemgrepOut;
  const SEV: Record<string, Severity> = { ERROR: "high", WARNING: "medium", INFO: "low" };
  return data.results.map((x) => {
    const cweRaw = Array.isArray(x.extra.metadata?.cwe) ? x.extra.metadata?.cwe[0] : x.extra.metadata?.cwe;
    const cwe = Number(cweRaw?.match(/CWE-(\d+)/)?.[1] ?? NaN);
    return {
      title: x.extra.message.split("\n")[0]!.slice(0, 160),
      category: "Quellcode",
      kind: "suspicion" as const,
      severity: SEV[x.extra.severity] ?? "low",
      confidence: "low" as const,
      checkId: "WA-REPO-03",
      affectedFile: rel(dir, x.path),
      affectedLine: x.start.line,
      tool: "semgrep",
      toolVersion: version,
      ruleId: `semgrep:${x.check_id.split(".").slice(-1)[0]}`,
      authContext: "repository",
      evidence: redact(`${rel(dir, x.path)}:${x.start.line}\n${x.extra.lines ?? ""}`, { knownSecrets: ctx.knownSecrets, maxLength: 800 }),
      description: x.extra.message,
      remediation: "Codestelle prüfen; wenn das Muster tatsächlich ausnutzbar ist, auf eine sichere API umstellen (siehe Regelbeschreibung).",
      limitations: "Statische Mustererkennung ohne Datenflussbeweis – Verifikation erforderlich.",
      references: refsForCheck("WA-REPO-03"),
      externalLinks: [],
      cweId: Number.isFinite(cwe) ? cwe : undefined,
    };
  });
}

export async function toolVersion(cmd: string, args: string[]): Promise<string> {
  try {
    const r = await execFileSafe(cmd, args, { timeoutMs: 30_000, env: { PATH: process.env.PATH, HOME: os.tmpdir() } });
    const m = (r.stdout + r.stderr).match(/v?(\d+\.\d+\.\d+)/);
    return m?.[1] ?? "unbekannt";
  } catch {
    return "unbekannt";
  }
}

export type RepoScanResult = { findings: RawFinding[]; coverage: CoverageEntry[]; commit: string; versions: Record<string, string>; unavailable: { adapter: string; reason: string }[]; executed: string[] };
