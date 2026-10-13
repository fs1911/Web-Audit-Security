import http from "node:http";
import type { AddressInfo } from "node:net";
import { sql } from "drizzle-orm";
import { getDb } from "../src/lib/db";
import { loadPolicy, type NetguardPolicy } from "../src/lib/security/netguard";

export async function resetDb() {
  const db = getDb();
  await db.execute(sql`TRUNCATE users, sessions, organizations, memberships, sites, site_hosts, credentials, scan_approvals, scans, scan_jobs, findings, finding_status_history, coverage_results, reports, scan_events, audit_log CASCADE`);
  return db;
}

/** Policy, die lokale Testserver auf 127.0.0.1 erlaubt (wie NETGUARD_TEST_ALLOW_* in Entwicklung). */
export function localPolicy(ports: number[]): NetguardPolicy {
  return loadPolicy({ NODE_ENV: "test", NETGUARD_TEST_ALLOW_CIDRS: "127.0.0.1/32", NETGUARD_TEST_ALLOW_PORTS: ports.join(",") } as NodeJS.ProcessEnv);
}

export async function startServer(handler: http.RequestListener): Promise<{ port: number; close: () => Promise<void> }> {
  const server = http.createServer(handler);
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  const port = (server.address() as AddressInfo).port;
  return { port, close: () => new Promise((r) => server.close(() => r())) };
}
