import { z } from "zod";
import referencesJson from "../../catalog/references.json";
import checksJson from "../../catalog/checks.json";
import type { ReferenceMapping } from "./db/schema";

const ReferenceSchema = z.object({
  id: z.string(),
  name: z.string(),
  version: z.string(),
  source: z.string().url(),
  adoptedAt: z.string().regex(/^\d{4}-\d{2}-\d{2}$/),
  license: z.string(),
  usage: z.string(),
  role: z.string(),
});

const CheckSchema = z.object({
  id: z.string().regex(/^WA-[A-Z]+-[A-Z0-9]+$/),
  title: z.string(),
  modes: z.array(z.enum(["baseline", "authenticated", "active", "repository"])),
  method: z.string(),
  automation: z.enum(["automatic", "partial", "manual"]),
  implemented: z.boolean(),
  inputs: z.array(z.string()),
  refs: z.array(z.tuple([z.string(), z.string(), z.string(), z.boolean()])),
  limitations: z.string(),
});

export type CatalogReference = z.infer<typeof ReferenceSchema>;
export type CatalogCheck = z.infer<typeof CheckSchema>;
export type ScanMode = "baseline" | "authenticated" | "active" | "repository";

export const CATALOG_VERSION = checksJson.catalogVersion;
export const REFERENCES: CatalogReference[] = z.array(ReferenceSchema).parse(referencesJson.references);
export const CHECKS: CatalogCheck[] = z.array(CheckSchema).parse(checksJson.checks);

export function checkById(id: string): CatalogCheck | undefined {
  return CHECKS.find((c) => c.id === id);
}

export function refsForCheck(id: string): ReferenceMapping[] {
  const c = checkById(id);
  if (!c) return [];
  return c.refs.map(([framework, version, rid, verified]) => ({ framework, version, id: rid, verified }));
}

export function checksForMode(mode: ScanMode): CatalogCheck[] {
  return CHECKS.filter((c) => c.implemented && c.modes.includes(mode));
}

export const AUTOMATION_LABEL = { automatic: "Automatisch", partial: "Teilweise automatisch", manual: "Manuell" } as const;
export const COVERAGE_LABEL = { tested: "Geprüft", not_tested: "Nicht geprüft", not_applicable: "Nicht anwendbar", error: "Fehler bei der Prüfung" } as const;
