import { sql } from "drizzle-orm";
import { boolean, index, integer, jsonb, pgEnum, pgTable, text, timestamp, uniqueIndex, uuid } from "drizzle-orm/pg-core";

export const roleEnum = pgEnum("member_role", ["owner", "admin", "auditor", "viewer"]);
export const environmentEnum = pgEnum("site_environment", ["production", "staging", "development"]);
export const verificationMethodEnum = pgEnum("verification_method", ["dns_txt", "file"]);
export const scanModeEnum = pgEnum("scan_mode", ["baseline", "authenticated", "active", "repository"]);
export const scanStatusEnum = pgEnum("scan_status", ["queued", "running", "cancel_requested", "cancelled", "completed", "failed"]);
export const findingKindEnum = pgEnum("finding_kind", ["vulnerability", "configuration", "suspicion", "informational"]);
export const severityEnum = pgEnum("severity", ["critical", "high", "medium", "low", "info"]);
export const confidenceEnum = pgEnum("confidence", ["confirmed", "high", "medium", "low"]);
export const findingStatusEnum = pgEnum("finding_status", ["open", "in_progress", "fixed", "false_positive", "risk_accepted"]);
export const coverageStateEnum = pgEnum("coverage_state", ["tested", "not_tested", "not_applicable", "error"]);

const created = () => timestamp("created_at", { withTimezone: true }).notNull().defaultNow();

export const users = pgTable("users", {
  id: uuid("id").primaryKey().defaultRandom(),
  email: text("email").notNull(),
  name: text("name").notNull(),
  passwordHash: text("password_hash").notNull(),
  createdAt: created(),
}, (t) => [uniqueIndex("users_email_uq").on(sql`lower(${t.email})`)]);

export const sessions = pgTable("sessions", {
  id: text("id").primaryKey(), // sha256 des Session-Tokens; das Token selbst wird nie gespeichert
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  expiresAt: timestamp("expires_at", { withTimezone: true }).notNull(),
  createdAt: created(),
});

export const organizations = pgTable("organizations", {
  id: uuid("id").primaryKey().defaultRandom(),
  name: text("name").notNull(),
  aiEnabled: boolean("ai_enabled").notNull().default(false),
  retentionDays: integer("retention_days").notNull().default(180),
  createdAt: created(),
});

export const memberships = pgTable("memberships", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  userId: uuid("user_id").notNull().references(() => users.id, { onDelete: "cascade" }),
  role: roleEnum("role").notNull(),
  createdAt: created(),
}, (t) => [uniqueIndex("memberships_org_user_uq").on(t.orgId, t.userId)]);

export const sites = pgTable("sites", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  name: text("name").notNull(),
  baseUrl: text("base_url").notNull(),
  environment: environmentEnum("environment").notNull(),
  ownerName: text("owner_name").notNull(),
  includePaths: jsonb("include_paths").$type<string[]>().notNull().default(["/"]),
  excludePaths: jsonb("exclude_paths").$type<string[]>().notNull().default([]),
  apiSpecUrl: text("api_spec_url"),
  repoUrl: text("repo_url"),
  authorizationConfirmedBy: uuid("authorization_confirmed_by").references(() => users.id),
  authorizationConfirmedAt: timestamp("authorization_confirmed_at", { withTimezone: true }),
  authorizationStatement: text("authorization_statement"),
  createdAt: created(),
}, (t) => [index("sites_org_idx").on(t.orgId)]);

export const siteHosts = pgTable("site_hosts", {
  id: uuid("id").primaryKey().defaultRandom(),
  siteId: uuid("site_id").notNull().references(() => sites.id, { onDelete: "cascade" }),
  host: text("host").notNull(),
  verificationToken: text("verification_token").notNull(),
  verificationMethod: verificationMethodEnum("verification_method"),
  verifiedAt: timestamp("verified_at", { withTimezone: true }),
  lastCheckAt: timestamp("last_check_at", { withTimezone: true }),
  lastCheckResult: text("last_check_result"),
  createdAt: created(),
}, (t) => [uniqueIndex("site_hosts_site_host_uq").on(t.siteId, t.host)]);

export const credentials = pgTable("credentials", {
  id: uuid("id").primaryKey().defaultRandom(),
  siteId: uuid("site_id").notNull().references(() => sites.id, { onDelete: "cascade" }),
  label: text("label").notNull(), // z. B. Testrolle «Redaktor»
  kind: text("kind").$type<"header" | "cookie" | "github_token">().notNull(),
  headerName: text("header_name"),
  encryptedValue: text("encrypted_value").notNull(),
  verifyUrl: text("verify_url"), // geschützte Seite zur Sitzungsprüfung
  logoutUrl: text("logout_url"),
  createdBy: uuid("created_by").references(() => users.id),
  createdAt: created(),
});

export const scanApprovals = pgTable("scan_approvals", {
  id: uuid("id").primaryKey().defaultRandom(),
  siteId: uuid("site_id").notNull().references(() => sites.id, { onDelete: "cascade" }),
  mode: scanModeEnum("mode").notNull(),
  profile: text("profile").notNull(),
  targetUrl: text("target_url").notNull(),
  scopeSummary: text("scope_summary").notNull(),
  windowStart: timestamp("window_start", { withTimezone: true }).notNull(),
  windowEnd: timestamp("window_end", { withTimezone: true }).notNull(),
  maxRequests: integer("max_requests").notNull(),
  requestsPerSecond: integer("requests_per_second").notNull(),
  allowWriteEffects: boolean("allow_write_effects").notNull().default(false),
  approvedBy: uuid("approved_by").notNull().references(() => users.id),
  statement: text("statement").notNull(),
  revokedAt: timestamp("revoked_at", { withTimezone: true }),
  createdAt: created(),
});

export type ScanLimits = { maxDurationMinutes: number; maxRequests: number; requestsPerSecond: number; maxDepth: number; maxChildren: number; threads: number };

export const scans = pgTable("scans", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  siteId: uuid("site_id").notNull().references(() => sites.id, { onDelete: "cascade" }),
  mode: scanModeEnum("mode").notNull(),
  status: scanStatusEnum("status").notNull().default("queued"),
  phase: text("phase"),
  progress: integer("progress").notNull().default(0),
  limits: jsonb("limits").$type<ScanLimits>().notNull(),
  scopeSnapshot: jsonb("scope_snapshot").$type<{ hosts: string[]; includePaths: string[]; excludePaths: string[] }>().notNull(),
  approvalId: uuid("approval_id").references(() => scanApprovals.id),
  credentialIds: jsonb("credential_ids").$type<string[]>().notNull().default([]),
  toolVersions: jsonb("tool_versions").$type<Record<string, string>>().notNull().default({}),
  executedMethods: jsonb("executed_methods").$type<string[]>().notNull().default([]),
  unavailableAdapters: jsonb("unavailable_adapters").$type<{ adapter: string; reason: string }[]>().notNull().default([]),
  egressStats: jsonb("egress_stats").$type<{ allowed: number; blocked: number; blockedSamples: { target: string; reason: string }[] }>(),
  commitSha: text("commit_sha"),
  previousScanId: uuid("previous_scan_id"),
  error: text("error"),
  startedBy: uuid("started_by").references(() => users.id),
  createdAt: created(),
  startedAt: timestamp("started_at", { withTimezone: true }),
  finishedAt: timestamp("finished_at", { withTimezone: true }),
  lastHeartbeatAt: timestamp("last_heartbeat_at", { withTimezone: true }),
}, (t) => [index("scans_site_idx").on(t.siteId), index("scans_org_idx").on(t.orgId)]);

export const scanJobs = pgTable("scan_jobs", {
  id: uuid("id").primaryKey().defaultRandom(),
  scanId: uuid("scan_id").notNull().references(() => scans.id, { onDelete: "cascade" }),
  state: text("state").$type<"pending" | "claimed" | "done">().notNull().default("pending"),
  attempts: integer("attempts").notNull().default(0),
  claimedAt: timestamp("claimed_at", { withTimezone: true }),
  runnerRef: text("runner_ref"),
  createdAt: created(),
}, (t) => [index("scan_jobs_state_idx").on(t.state)]);

export type ReferenceMapping = { framework: string; version: string; id: string; verified: boolean; note?: string };

export const findings = pgTable("findings", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  siteId: uuid("site_id").notNull().references(() => sites.id, { onDelete: "cascade" }),
  scanId: uuid("scan_id").notNull().references(() => scans.id, { onDelete: "cascade" }),
  fingerprint: text("fingerprint").notNull(),
  title: text("title").notNull(),
  category: text("category").notNull(),
  kind: findingKindEnum("kind").notNull(),
  severity: severityEnum("severity").notNull(),
  confidence: confidenceEnum("confidence").notNull(),
  checkId: text("check_id"),
  affectedUrl: text("affected_url"),
  affectedFile: text("affected_file"),
  affectedLine: integer("affected_line"),
  parameter: text("parameter"),
  method: text("method"),
  tool: text("tool").notNull(),
  toolVersion: text("tool_version"),
  ruleId: text("rule_id").notNull(),
  authContext: text("auth_context").notNull().default("anonym"),
  evidence: text("evidence").notNull(),
  description: text("description").notNull(),
  impact: text("impact"),
  prerequisites: text("prerequisites"),
  limitations: text("limitations"),
  remediation: text("remediation").notNull(),
  references: jsonb("references").$type<ReferenceMapping[]>().notNull().default([]),
  externalLinks: jsonb("external_links").$type<string[]>().notNull().default([]),
  cweId: integer("cwe_id"),
  cvssVersion: text("cvss_version"),
  cvssVector: text("cvss_vector"),
  cvssScore: text("cvss_score"),
  cvssRationale: text("cvss_rationale"),
  occurrences: integer("occurrences").notNull().default(1),
  otherUrls: jsonb("other_urls").$type<string[]>().notNull().default([]),
  status: findingStatusEnum("status").notNull().default("open"),
  assignee: text("assignee"),
  dueDate: timestamp("due_date", { withTimezone: true }),
  retestResult: text("retest_result"),
  aiExplanation: jsonb("ai_explanation").$type<{ model: string; createdAt: string; summary: string; steps: string[] } | null>(),
  detectedAt: timestamp("detected_at", { withTimezone: true }).notNull().defaultNow(),
}, (t) => [index("findings_scan_idx").on(t.scanId), index("findings_site_fp_idx").on(t.siteId, t.fingerprint)]);

export const findingStatusHistory = pgTable("finding_status_history", {
  id: uuid("id").primaryKey().defaultRandom(),
  findingId: uuid("finding_id").notNull().references(() => findings.id, { onDelete: "cascade" }),
  fromStatus: findingStatusEnum("from_status"),
  toStatus: findingStatusEnum("to_status").notNull(),
  comment: text("comment"),
  changedBy: uuid("changed_by").references(() => users.id),
  createdAt: created(),
});

export const coverageResults = pgTable("coverage_results", {
  id: uuid("id").primaryKey().defaultRandom(),
  scanId: uuid("scan_id").notNull().references(() => scans.id, { onDelete: "cascade" }),
  checkId: text("check_id").notNull(),
  state: coverageStateEnum("state").notNull(),
  method: text("method"),
  evidence: text("evidence"),
  limitation: text("limitation"),
}, (t) => [uniqueIndex("coverage_scan_check_uq").on(t.scanId, t.checkId)]);

export const reports = pgTable("reports", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").notNull().references(() => organizations.id, { onDelete: "cascade" }),
  scanId: uuid("scan_id").notNull().references(() => scans.id, { onDelete: "cascade" }),
  format: text("format").$type<"pdf" | "json">().notNull(),
  objectKey: text("object_key").notNull(),
  sha256: text("sha256").notNull(),
  sizeBytes: integer("size_bytes").notNull(),
  createdBy: uuid("created_by").references(() => users.id),
  createdAt: created(),
});

export const scanEvents = pgTable("scan_events", {
  id: uuid("id").primaryKey().defaultRandom(),
  scanId: uuid("scan_id").notNull().references(() => scans.id, { onDelete: "cascade" }),
  level: text("level").$type<"info" | "warn" | "error">().notNull(),
  message: text("message").notNull(),
  createdAt: created(),
}, (t) => [index("scan_events_scan_idx").on(t.scanId)]);

export const auditLog = pgTable("audit_log", {
  id: uuid("id").primaryKey().defaultRandom(),
  orgId: uuid("org_id").references(() => organizations.id, { onDelete: "cascade" }),
  userId: uuid("user_id").references(() => users.id, { onDelete: "set null" }),
  action: text("action").notNull(),
  targetType: text("target_type"),
  targetId: text("target_id"),
  details: jsonb("details").$type<Record<string, unknown>>().notNull().default({}),
  ip: text("ip"),
  createdAt: created(),
}, (t) => [index("audit_org_idx").on(t.orgId)]);
