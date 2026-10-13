import { CONFIDENCE_LABEL, KIND_LABEL, SEVERITY_LABEL, STATUS_LABEL, type Confidence, type FindingKind, type Severity } from "@/lib/findings/types";

const SEV_CLASS: Record<Severity, string> = {
  critical: "bg-red-800 text-white",
  high: "bg-red-600 text-white",
  medium: "bg-amber-500 text-white",
  low: "bg-yellow-200 text-yellow-900",
  info: "bg-slate-200 text-slate-700",
};

export function SeverityBadge({ s }: { s: Severity }) {
  return <span className={`inline-block rounded px-2 py-0.5 text-xs font-semibold ${SEV_CLASS[s]}`}>{SEVERITY_LABEL[s]}</span>;
}

export function ConfidenceBadge({ c }: { c: Confidence }) {
  return <span className="inline-block rounded border border-slate-300 px-2 py-0.5 text-xs text-slate-600">Vertrauen: {CONFIDENCE_LABEL[c]}</span>;
}

const KIND_CLASS: Record<FindingKind, string> = {
  vulnerability: "bg-red-50 text-red-800 border-red-200",
  configuration: "bg-blue-50 text-blue-800 border-blue-200",
  suspicion: "bg-purple-50 text-purple-800 border-purple-200",
  informational: "bg-slate-50 text-slate-600 border-slate-200",
};

export function KindBadge({ k }: { k: FindingKind }) {
  return <span className={`inline-block rounded border px-2 py-0.5 text-xs ${KIND_CLASS[k]}`}>{KIND_LABEL[k]}</span>;
}

export function StatusBadge({ s }: { s: keyof typeof STATUS_LABEL }) {
  return <span className="inline-block rounded bg-slate-100 px-2 py-0.5 text-xs text-slate-700">{STATUS_LABEL[s]}</span>;
}

const SCAN_STATUS: Record<string, [string, string]> = {
  queued: ["In Warteschlange", "bg-slate-200 text-slate-700"],
  running: ["Läuft", "bg-blue-100 text-blue-800"],
  cancel_requested: ["Abbruch angefordert", "bg-amber-100 text-amber-800"],
  cancelled: ["Abgebrochen", "bg-slate-300 text-slate-800"],
  completed: ["Abgeschlossen", "bg-green-100 text-green-800"],
  failed: ["Fehlgeschlagen", "bg-red-100 text-red-800"],
};

export function ScanStatusBadge({ s }: { s: string }) {
  const [label, cls] = SCAN_STATUS[s] ?? [s, "bg-slate-100"];
  return <span className={`inline-block rounded px-2 py-0.5 text-xs font-medium ${cls}`}>{label}</span>;
}

export const MODE_LABEL: Record<string, string> = {
  baseline: "A – Schonender Basischeck",
  authenticated: "B – Authentifizierter Check",
  active: "C – Aktiver Check",
  repository: "D – Repository-Check",
};

export const ENV_LABEL: Record<string, string> = { production: "Produktion", staging: "Staging", development: "Entwicklung" };

export function Alert({ kind = "info", children }: { kind?: "info" | "warn" | "error" | "success"; children: React.ReactNode }) {
  const cls = { info: "border-blue-200 bg-blue-50 text-blue-900", warn: "border-amber-300 bg-amber-50 text-amber-900", error: "border-red-300 bg-red-50 text-red-900", success: "border-green-300 bg-green-50 text-green-900" }[kind];
  return <div className={`rounded-md border px-4 py-3 text-sm ${cls}`}>{children}</div>;
}

export function ErrorFromQuery({ error, ok }: { error?: string; ok?: string }) {
  return (
    <>
      {error ? <Alert kind="error">{error}</Alert> : null}
      {ok ? <Alert kind="success">{ok}</Alert> : null}
    </>
  );
}

export function fmtDate(d: Date | string | null | undefined): string {
  if (!d) return "–";
  const x = typeof d === "string" ? new Date(d) : d;
  return x.toLocaleString("de-CH", { timeZone: "Europe/Zurich", dateStyle: "medium", timeStyle: "short" });
}
