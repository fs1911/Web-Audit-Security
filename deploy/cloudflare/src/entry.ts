/**
 * Cloudflare-Worker-Einstieg für «web-audit-security».
 * STATUS: Entwurf, nicht deployt und nicht gegen Cloudflare getestet (siehe docs/deployment.md).
 *
 * - fetch:      Next.js-App über den OpenNext-Adapter (Build: `npx opennextjs-cloudflare build`)
 * - scheduled:  Dispatcher (Postgres-Queue → Container), Beenden hängender Scans
 * - Container:  ScanRunnerContainer führt src/runner/server.ts mit ZAP aus
 *
 * Egress-Entscheid (dokumentierter Zielkonflikt):
 * Cloudflare filtert HTTPS-Ziele netzwerkseitig nur mit TLS-Interception (interceptHttps).
 * Interception würde die TLS-/Zertifikatsprüfungen verfälschen. Standard ist daher
 * EGRESS_MODE="app": Internetzugang an, Schutz durch Netguard + Egress-Proxy im Runner
 * (DNS-/IP-Prüfung pro Verbindung). EGRESS_MODE="intercept" schaltet die netzwerkseitige
 * Host-Allowlist ein; TLS-Prüfpunkte werden dann im Bericht als «nicht geprüft» geführt
 * (noch nicht implementiert → derzeit nicht verwenden).
 */
// @ts-nocheck – Typen kommen erst mit @cloudflare/workers-types / OpenNext-Build
import { Container, getContainer } from "@cloudflare/containers";
// Wird von `opennextjs-cloudflare build` erzeugt
import openNext from "../../../.open-next/worker.js";

export class ScanRunnerContainer extends Container {
  defaultPort = 8787;
  sleepAfter = "30m";
  enableInternet = true; // siehe Egress-Entscheid oben
  envVars = {
    RUNNER_HOST: "0.0.0.0",
    RUNNER_PORT: "8787",
    WEBAUDIT_ENV: "production",
    NODE_ENV: "production",
  };
}

async function dispatch(env: Env) {
  // Nutzt denselben Code wie der lokale Dispatcher (src/worker/main.ts), aber mit Container-Ziel.
  process.env.DATABASE_URL = env.HYPERDRIVE.connectionString;
  const { getDb } = await import("../../../src/lib/db");
  const { claimNextJob, buildJobSpec, failStaleScans } = await import("../../../src/lib/scans/service");
  const { scans, scanJobs } = await import("../../../src/lib/db/schema");
  const { eq } = await import("drizzle-orm");
  const db = getDb();
  await failStaleScans(db);
  for (let i = 0; i < 5; i++) {
    const claimed = await claimNextJob(db);
    if (!claimed) return;
    const [scan] = await db.select().from(scans).where(eq(scans.id, claimed.scanId));
    const spec = await buildJobSpec(db, claimed.jobId, scan);
    const runner = getContainer(env.SCAN_RUNNER, claimed.jobId);
    const res = await runner.fetch("http://runner/jobs", {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${env.RUNNER_SHARED_SECRET}` },
      body: JSON.stringify(spec),
    });
    if (res.status === 202) {
      await db.update(scanJobs).set({ runnerRef: `container:${claimed.jobId}` }).where(eq(scanJobs.id, claimed.jobId));
      await db.update(scans).set({ status: "running", startedAt: new Date(), lastHeartbeatAt: new Date(), phase: "An Scan-Container übergeben" }).where(eq(scans.id, scan.id));
    } else {
      await db.update(scans).set({ status: "failed", phase: "Fehlgeschlagen", error: `Scan-Container lehnte Job ab (HTTP ${res.status}). Keine Ergebnisse erzeugt.`, finishedAt: new Date() }).where(eq(scans.id, scan.id));
      await db.update(scanJobs).set({ state: "done" }).where(eq(scanJobs.id, claimed.jobId));
    }
  }
}

export default {
  fetch: openNext.fetch,
  async scheduled(_event: ScheduledEvent, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(dispatch(env));
  },
};
