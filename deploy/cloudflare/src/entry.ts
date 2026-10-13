/**
 * Cloudflare-Worker-Einstieg für «web-audit-security».
 *
 * - fetch:      Next.js-App über den OpenNext-Adapter (`npm run cf:build` erzeugt .open-next/worker.js)
 * - scheduled:  Dispatcher jede Minute: Postgres-Queue → Scan-Container; hängende Scans beenden
 * - Container:  ScanRunnerContainer führt src/runner/server.ts mit OWASP ZAP aus (Image: deploy/docker/Dockerfile.runner)
 *
 * Egress-Entscheid (siehe docs/deployment.md): enableInternet=true, Schutz anwendungsseitig
 * (Netguard + Egress-Proxy im Runner). TLS-Interception würde die Zertifikatsprüfungen verfälschen.
 */
import { Container, getContainer } from "@cloudflare/containers";
import { eq } from "drizzle-orm";
// @ts-expect-error – wird erst durch `opennextjs-cloudflare build` erzeugt
import openNext from "../../../.open-next/worker.js";
import { withDbConnection, getDb } from "../../../src/lib/db";
import { scanJobs, scans } from "../../../src/lib/db/schema";
import { buildJobSpec, claimNextJob, failStaleScans } from "../../../src/lib/scans/service";

type Env = {
  HYPERDRIVE: { connectionString: string };
  SCAN_RUNNER: DurableObjectNamespace<ScanRunnerContainer>;
  RUNNER_SHARED_SECRET: string;
  [k: string]: unknown;
};

export class ScanRunnerContainer extends Container<Env> {
  defaultPort = 8787;
  sleepAfter = "15m";
  enableInternet = true;
  constructor(ctx: DurableObjectState, env: Env) {
    super(ctx, env, {
      envVars: {
        RUNNER_HOST: "0.0.0.0",
        RUNNER_PORT: "8787",
        RUNNER_MAX_CONCURRENT: "1",
        RUNNER_SHARED_SECRET: env.RUNNER_SHARED_SECRET,
        NODE_ENV: "production",
        WEBAUDIT_ENV: "production",
      },
    });
  }
}

async function dispatch(env: Env): Promise<void> {
  await withDbConnection(env.HYPERDRIVE.connectionString, async () => {
    const db = getDb();
    const stale = await failStaleScans(db);
    if (stale) console.log(`[dispatcher] ${stale} Scan(s) ohne Rückmeldung beendet`);
    for (let i = 0; i < 5; i++) {
      const claimed = await claimNextJob(db);
      if (!claimed) return;
      const [scan] = await db.select().from(scans).where(eq(scans.id, claimed.scanId));
      if (!scan) continue;
      try {
        const spec = await buildJobSpec(db, claimed.jobId, scan);
        // Ein Container pro Job (Name = Job-ID) → Isolation zwischen Scans
        const runner = getContainer(env.SCAN_RUNNER, claimed.jobId);
        await runner.startAndWaitForPorts();
        const res = await runner.fetch(
          new Request("http://runner/jobs", {
            method: "POST",
            headers: { "content-type": "application/json", authorization: `Bearer ${env.RUNNER_SHARED_SECRET}` },
            body: JSON.stringify(spec),
          }),
        );
        if (res.status !== 202) throw new Error(`Scan-Container lehnte Job ab (HTTP ${res.status})`);
        await db.update(scanJobs).set({ runnerRef: `container:${claimed.jobId}` }).where(eq(scanJobs.id, claimed.jobId));
        await db.update(scans).set({ status: "running", startedAt: new Date(), lastHeartbeatAt: new Date(), phase: "An Scan-Container übergeben" }).where(eq(scans.id, scan.id));
        console.log(`[dispatcher] Scan ${scan.id} an Container übergeben`);
      } catch (e) {
        await db.update(scans).set({ status: "failed", phase: "Fehlgeschlagen", error: `Scan-Container nicht verfügbar: ${(e as Error).message}. Es wurden keine Ergebnisse erzeugt.`, finishedAt: new Date() }).where(eq(scans.id, scan.id));
        await db.update(scanJobs).set({ state: "done" }).where(eq(scanJobs.id, claimed.jobId));
        console.error(`[dispatcher] Scan ${scan.id} fehlgeschlagen: ${(e as Error).message}`);
      }
    }
  });
}

export default {
  fetch: (openNext as { fetch: ExportedHandlerFetchHandler<Env> }).fetch,
  async scheduled(_event: ScheduledController, env: Env, ctx: ExecutionContext) {
    ctx.waitUntil(dispatch(env));
  },
} satisfies ExportedHandler<Env>;
