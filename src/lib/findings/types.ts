import type { ReferenceMapping } from "../db/schema";

export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type Confidence = "confirmed" | "high" | "medium" | "low";
export type FindingKind = "vulnerability" | "configuration" | "suspicion" | "informational";

/** Normalisierte Feststellung, wie sie Runner-Adapter liefern (vor Persistenz). */
export type RawFinding = {
  title: string;
  category: string;
  kind: FindingKind;
  severity: Severity;
  confidence: Confidence;
  checkId?: string;
  affectedUrl?: string;
  affectedFile?: string;
  affectedLine?: number;
  parameter?: string;
  method?: string;
  tool: string;
  toolVersion?: string;
  ruleId: string;
  authContext: string;
  evidence: string;
  description: string;
  impact?: string;
  prerequisites?: string;
  limitations?: string;
  remediation: string;
  references: ReferenceMapping[];
  externalLinks: string[];
  cweId?: number;
  cvss?: { version: string; vector: string; score: string; rationale: string };
  /** Weitere Fundstellen derselben Feststellung (z. B. aus ZAP zusammengeführt). */
  otherUrls?: string[];
};

export type CoverageEntry = {
  checkId: string;
  state: "tested" | "not_tested" | "not_applicable" | "error";
  method?: string;
  evidence?: string;
  limitation?: string;
};

export const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: "Kritisch",
  high: "Hoch",
  medium: "Mittel",
  low: "Niedrig",
  info: "Information",
};

export const CONFIDENCE_LABEL: Record<Confidence, string> = {
  confirmed: "Bestätigt",
  high: "Hoch",
  medium: "Mittel",
  low: "Niedrig",
};

export const KIND_LABEL: Record<FindingKind, string> = {
  vulnerability: "Sicherheitslücke",
  configuration: "Konfigurationshinweis",
  suspicion: "Verdacht – Verifikation erforderlich",
  informational: "Information",
};

export const STATUS_LABEL = {
  open: "Offen",
  in_progress: "In Bearbeitung",
  fixed: "Behoben",
  false_positive: "Fehlalarm",
  risk_accepted: "Risiko akzeptiert",
} as const;
