-- Supabase stellt Tabellen im Schema "public" über die Data API (PostgREST) bereit.
-- RLS ohne Policies sperrt diesen Weg vollständig. Die App verbindet sich als Tabelleneigentümer
-- (über Hyperdrive) und ist davon nicht betroffen (RLS gilt nicht für den Eigentümer ohne FORCE).
ALTER TABLE "users" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "sessions" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "organizations" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "memberships" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "sites" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "site_hosts" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "credentials" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "scan_approvals" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "scans" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "scan_jobs" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "findings" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "finding_status_history" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "coverage_results" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "reports" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "scan_events" ENABLE ROW LEVEL SECURITY;--> statement-breakpoint
ALTER TABLE "audit_log" ENABLE ROW LEVEL SECURITY;
