CREATE TYPE "public"."confidence" AS ENUM('confirmed', 'high', 'medium', 'low');--> statement-breakpoint
CREATE TYPE "public"."coverage_state" AS ENUM('tested', 'not_tested', 'not_applicable', 'error');--> statement-breakpoint
CREATE TYPE "public"."site_environment" AS ENUM('production', 'staging', 'development');--> statement-breakpoint
CREATE TYPE "public"."finding_kind" AS ENUM('vulnerability', 'configuration', 'suspicion', 'informational');--> statement-breakpoint
CREATE TYPE "public"."finding_status" AS ENUM('open', 'in_progress', 'fixed', 'false_positive', 'risk_accepted');--> statement-breakpoint
CREATE TYPE "public"."member_role" AS ENUM('owner', 'admin', 'auditor', 'viewer');--> statement-breakpoint
CREATE TYPE "public"."scan_mode" AS ENUM('baseline', 'authenticated', 'active', 'repository');--> statement-breakpoint
CREATE TYPE "public"."scan_status" AS ENUM('queued', 'running', 'cancel_requested', 'cancelled', 'completed', 'failed');--> statement-breakpoint
CREATE TYPE "public"."severity" AS ENUM('critical', 'high', 'medium', 'low', 'info');--> statement-breakpoint
CREATE TYPE "public"."verification_method" AS ENUM('dns_txt', 'file');--> statement-breakpoint
CREATE TABLE "audit_log" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid,
	"user_id" uuid,
	"action" text NOT NULL,
	"target_type" text,
	"target_id" text,
	"details" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"ip" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "coverage_results" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"scan_id" uuid NOT NULL,
	"check_id" text NOT NULL,
	"state" "coverage_state" NOT NULL,
	"method" text,
	"evidence" text,
	"limitation" text
);
--> statement-breakpoint
CREATE TABLE "credentials" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"site_id" uuid NOT NULL,
	"label" text NOT NULL,
	"kind" text NOT NULL,
	"header_name" text,
	"encrypted_value" text NOT NULL,
	"verify_url" text,
	"logout_url" text,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "finding_status_history" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"finding_id" uuid NOT NULL,
	"from_status" "finding_status",
	"to_status" "finding_status" NOT NULL,
	"comment" text,
	"changed_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "findings" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"site_id" uuid NOT NULL,
	"scan_id" uuid NOT NULL,
	"fingerprint" text NOT NULL,
	"title" text NOT NULL,
	"category" text NOT NULL,
	"kind" "finding_kind" NOT NULL,
	"severity" "severity" NOT NULL,
	"confidence" "confidence" NOT NULL,
	"check_id" text,
	"affected_url" text,
	"affected_file" text,
	"affected_line" integer,
	"parameter" text,
	"method" text,
	"tool" text NOT NULL,
	"tool_version" text,
	"rule_id" text NOT NULL,
	"auth_context" text DEFAULT 'anonym' NOT NULL,
	"evidence" text NOT NULL,
	"description" text NOT NULL,
	"impact" text,
	"prerequisites" text,
	"limitations" text,
	"remediation" text NOT NULL,
	"references" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"external_links" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"cwe_id" integer,
	"cvss_version" text,
	"cvss_vector" text,
	"cvss_score" text,
	"cvss_rationale" text,
	"occurrences" integer DEFAULT 1 NOT NULL,
	"other_urls" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"status" "finding_status" DEFAULT 'open' NOT NULL,
	"assignee" text,
	"due_date" timestamp with time zone,
	"retest_result" text,
	"ai_explanation" jsonb,
	"detected_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "memberships" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"user_id" uuid NOT NULL,
	"role" "member_role" NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "organizations" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"name" text NOT NULL,
	"ai_enabled" boolean DEFAULT false NOT NULL,
	"retention_days" integer DEFAULT 180 NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "reports" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"scan_id" uuid NOT NULL,
	"format" text NOT NULL,
	"object_key" text NOT NULL,
	"sha256" text NOT NULL,
	"size_bytes" integer NOT NULL,
	"created_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scan_approvals" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"site_id" uuid NOT NULL,
	"mode" "scan_mode" NOT NULL,
	"profile" text NOT NULL,
	"target_url" text NOT NULL,
	"scope_summary" text NOT NULL,
	"window_start" timestamp with time zone NOT NULL,
	"window_end" timestamp with time zone NOT NULL,
	"max_requests" integer NOT NULL,
	"requests_per_second" integer NOT NULL,
	"allow_write_effects" boolean DEFAULT false NOT NULL,
	"approved_by" uuid NOT NULL,
	"statement" text NOT NULL,
	"revoked_at" timestamp with time zone,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scan_events" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"scan_id" uuid NOT NULL,
	"level" text NOT NULL,
	"message" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scan_jobs" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"scan_id" uuid NOT NULL,
	"state" text DEFAULT 'pending' NOT NULL,
	"attempts" integer DEFAULT 0 NOT NULL,
	"claimed_at" timestamp with time zone,
	"runner_ref" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "scans" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"site_id" uuid NOT NULL,
	"mode" "scan_mode" NOT NULL,
	"status" "scan_status" DEFAULT 'queued' NOT NULL,
	"phase" text,
	"progress" integer DEFAULT 0 NOT NULL,
	"limits" jsonb NOT NULL,
	"scope_snapshot" jsonb NOT NULL,
	"approval_id" uuid,
	"credential_ids" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"tool_versions" jsonb DEFAULT '{}'::jsonb NOT NULL,
	"executed_methods" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"unavailable_adapters" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"egress_stats" jsonb,
	"commit_sha" text,
	"previous_scan_id" uuid,
	"error" text,
	"started_by" uuid,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL,
	"started_at" timestamp with time zone,
	"finished_at" timestamp with time zone,
	"last_heartbeat_at" timestamp with time zone
);
--> statement-breakpoint
CREATE TABLE "sessions" (
	"id" text PRIMARY KEY NOT NULL,
	"user_id" uuid NOT NULL,
	"expires_at" timestamp with time zone NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "site_hosts" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"site_id" uuid NOT NULL,
	"host" text NOT NULL,
	"verification_token" text NOT NULL,
	"verification_method" "verification_method",
	"verified_at" timestamp with time zone,
	"last_check_at" timestamp with time zone,
	"last_check_result" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "sites" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"org_id" uuid NOT NULL,
	"name" text NOT NULL,
	"base_url" text NOT NULL,
	"environment" "site_environment" NOT NULL,
	"owner_name" text NOT NULL,
	"include_paths" jsonb DEFAULT '["/"]'::jsonb NOT NULL,
	"exclude_paths" jsonb DEFAULT '[]'::jsonb NOT NULL,
	"api_spec_url" text,
	"repo_url" text,
	"authorization_confirmed_by" uuid,
	"authorization_confirmed_at" timestamp with time zone,
	"authorization_statement" text,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
CREATE TABLE "users" (
	"id" uuid PRIMARY KEY DEFAULT gen_random_uuid() NOT NULL,
	"email" text NOT NULL,
	"name" text NOT NULL,
	"password_hash" text NOT NULL,
	"created_at" timestamp with time zone DEFAULT now() NOT NULL
);
--> statement-breakpoint
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "audit_log" ADD CONSTRAINT "audit_log_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE set null ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "coverage_results" ADD CONSTRAINT "coverage_results_scan_id_scans_id_fk" FOREIGN KEY ("scan_id") REFERENCES "public"."scans"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_site_id_sites_id_fk" FOREIGN KEY ("site_id") REFERENCES "public"."sites"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "credentials" ADD CONSTRAINT "credentials_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding_status_history" ADD CONSTRAINT "finding_status_history_finding_id_findings_id_fk" FOREIGN KEY ("finding_id") REFERENCES "public"."findings"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "finding_status_history" ADD CONSTRAINT "finding_status_history_changed_by_users_id_fk" FOREIGN KEY ("changed_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_site_id_sites_id_fk" FOREIGN KEY ("site_id") REFERENCES "public"."sites"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "findings" ADD CONSTRAINT "findings_scan_id_scans_id_fk" FOREIGN KEY ("scan_id") REFERENCES "public"."scans"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "memberships" ADD CONSTRAINT "memberships_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "memberships" ADD CONSTRAINT "memberships_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "reports" ADD CONSTRAINT "reports_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "reports" ADD CONSTRAINT "reports_scan_id_scans_id_fk" FOREIGN KEY ("scan_id") REFERENCES "public"."scans"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "reports" ADD CONSTRAINT "reports_created_by_users_id_fk" FOREIGN KEY ("created_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_approvals" ADD CONSTRAINT "scan_approvals_site_id_sites_id_fk" FOREIGN KEY ("site_id") REFERENCES "public"."sites"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_approvals" ADD CONSTRAINT "scan_approvals_approved_by_users_id_fk" FOREIGN KEY ("approved_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_events" ADD CONSTRAINT "scan_events_scan_id_scans_id_fk" FOREIGN KEY ("scan_id") REFERENCES "public"."scans"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scan_jobs" ADD CONSTRAINT "scan_jobs_scan_id_scans_id_fk" FOREIGN KEY ("scan_id") REFERENCES "public"."scans"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scans" ADD CONSTRAINT "scans_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scans" ADD CONSTRAINT "scans_site_id_sites_id_fk" FOREIGN KEY ("site_id") REFERENCES "public"."sites"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scans" ADD CONSTRAINT "scans_approval_id_scan_approvals_id_fk" FOREIGN KEY ("approval_id") REFERENCES "public"."scan_approvals"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "scans" ADD CONSTRAINT "scans_started_by_users_id_fk" FOREIGN KEY ("started_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sessions" ADD CONSTRAINT "sessions_user_id_users_id_fk" FOREIGN KEY ("user_id") REFERENCES "public"."users"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "site_hosts" ADD CONSTRAINT "site_hosts_site_id_sites_id_fk" FOREIGN KEY ("site_id") REFERENCES "public"."sites"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sites" ADD CONSTRAINT "sites_org_id_organizations_id_fk" FOREIGN KEY ("org_id") REFERENCES "public"."organizations"("id") ON DELETE cascade ON UPDATE no action;--> statement-breakpoint
ALTER TABLE "sites" ADD CONSTRAINT "sites_authorization_confirmed_by_users_id_fk" FOREIGN KEY ("authorization_confirmed_by") REFERENCES "public"."users"("id") ON DELETE no action ON UPDATE no action;--> statement-breakpoint
CREATE INDEX "audit_org_idx" ON "audit_log" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "coverage_scan_check_uq" ON "coverage_results" USING btree ("scan_id","check_id");--> statement-breakpoint
CREATE INDEX "findings_scan_idx" ON "findings" USING btree ("scan_id");--> statement-breakpoint
CREATE INDEX "findings_site_fp_idx" ON "findings" USING btree ("site_id","fingerprint");--> statement-breakpoint
CREATE UNIQUE INDEX "memberships_org_user_uq" ON "memberships" USING btree ("org_id","user_id");--> statement-breakpoint
CREATE INDEX "scan_events_scan_idx" ON "scan_events" USING btree ("scan_id");--> statement-breakpoint
CREATE INDEX "scan_jobs_state_idx" ON "scan_jobs" USING btree ("state");--> statement-breakpoint
CREATE INDEX "scans_site_idx" ON "scans" USING btree ("site_id");--> statement-breakpoint
CREATE INDEX "scans_org_idx" ON "scans" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "site_hosts_site_host_uq" ON "site_hosts" USING btree ("site_id","host");--> statement-breakpoint
CREATE INDEX "sites_org_idx" ON "sites" USING btree ("org_id");--> statement-breakpoint
CREATE UNIQUE INDEX "users_email_uq" ON "users" USING btree (lower("email"));