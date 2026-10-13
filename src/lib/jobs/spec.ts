import type { ScanLimits } from "../db/schema";
import type { Scope } from "../security/scope";
import type { CoverageEntry, RawFinding } from "../findings/types";

export type AuthRoleSpec = {
  label: string;
  kind: "header" | "cookie";
  headerName?: string;
  /** Klartext nur im Arbeitsspeicher des Runners; wird nie geloggt oder gespeichert. */
  value: string;
  verifyUrl?: string;
  logoutUrl?: string;
};

export type JobSpec = {
  jobId: string;
  scanId: string;
  mode: "baseline" | "authenticated" | "active" | "repository";
  siteName: string;
  environment: string;
  baseUrl: string;
  scope: Scope;
  limits: ScanLimits;
  callbackUrl: string;
  callbackToken: string;
  auth?: { roles: AuthRoleSpec[] };
  repo?: { url: string; token?: string; ref?: string };
  active?: { approvalId: string; windowEnd: string; profile: "webaudit-safe"; allowWriteEffects: boolean };
  /** Nur für lokale Testziele ausserhalb production. */
  allowInvalidCerts?: boolean;
};

export type RunnerEvent =
  | { type: "heartbeat" }
  | { type: "progress"; phase: string; progress: number; message?: string; level?: "info" | "warn" | "error" }
  | { type: "results"; findings: RawFinding[]; coverage: CoverageEntry[] }
  | {
      type: "complete";
      toolVersions: Record<string, string>;
      executedMethods: string[];
      unavailableAdapters: { adapter: string; reason: string }[];
      egressStats?: { allowed: number; blocked: number; blockedSamples: { target: string; reason: string }[] };
      commitSha?: string;
      cancelled?: boolean;
    }
  | { type: "failed"; error: string; unavailableAdapters?: { adapter: string; reason: string }[] };

export const DEFAULT_LIMITS: ScanLimits = {
  maxDurationMinutes: 20,
  maxRequests: 1500,
  requestsPerSecond: 5,
  maxDepth: 5,
  maxChildren: 50,
  threads: 2,
};

export const HARD_LIMITS: ScanLimits = {
  maxDurationMinutes: 120,
  maxRequests: 20000,
  requestsPerSecond: 20,
  maxDepth: 10,
  maxChildren: 500,
  threads: 5,
};

export function clampLimits(l: Partial<ScanLimits>): ScanLimits {
  const out = { ...DEFAULT_LIMITS };
  for (const k of Object.keys(DEFAULT_LIMITS) as (keyof ScanLimits)[]) {
    const v = Number(l[k]);
    if (Number.isFinite(v) && v > 0) out[k] = Math.min(Math.floor(v), HARD_LIMITS[k]);
  }
  return out;
}
