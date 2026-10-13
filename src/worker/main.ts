import { eq } from "drizzle-orm";
import { getDb } from "../lib/db";
import { scanJobs, scans } from "../lib/db/schema";
import { buildJobSpec, claimNextJob, failStaleScans } from "../lib/scans/service";
import { redact } from "../lib/security/redact";

/**
 * Dispatcher: holt Jobs aus der Postgres-Queue (FOR UPDATE SKIP LOCKED) und übergibt sie
 * an den Scan-Runner. Läuft als eigener Prozess, getrennt von der Weboberfläche.
 * In Cloudflare wird diese Rolle vom Queue-Consumer übernommen (deploy/cloudflare).
 */

const RUNNER_URL = process.env.RUNNER_URL ?? "http://127.0.0.1:8787";
const POLL_MS = Number(process.env.DISPATCH_POLL_MS ?? 2000);
let stopping = false;

async function dispatchOnce(): Promise<boolean> {
  const db = getDb();
  const claimed = await claimNextJob(db);
  if (!claimed) return false;
  const [scan] = await db.select().from(scans).where(eq(scans.id, claimed.scanId));
  if (!scan) return true;
  try {
    const spec = await buildJobSpec(db, claimed.jobId, scan);
    const res = await fetch(`${RUNNER_URL}/jobs`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${process.env.RUNNER_SHARED_SECRET}` },
      body: JSON.stringify(spec),
      signal: AbortSignal.timeout(15_000),
    });
    if (res.status === 429) {
      // Runner ausgelastet → zurück in die Warteschlange
      await db.update(scanJobs).set({ state: "pending" }).where(eq(scanJobs.id, claimed.jobId));
      return false;
    }
    if (res.status !== 202) throw new Error(`Runner lehnte Job ab (HTTP ${res.status}): ${(await res.text()).slice(0, 200)}`);
    await db.update(scanJobs).set({ runnerRef: RUNNER_URL }).where(eq(scanJobs.id, claimed.jobId));
    await db.update(scans).set({ status: "running", startedAt: new Date(), lastHeartbeatAt: new Date(), phase: "An Scan-Worker übergeben" }).where(eq(scans.id, scan.id));
    console.log(`[dispatcher] Scan ${scan.id} an Runner übergeben`);
  } catch (e) {
    const msg = (e as Error).message;
    const reason = /fetch failed|ECONNREFUSED|timeout/i.test(msg) ? `Scan-Worker nicht erreichbar (${RUNNER_URL}). Es wurden keine Ergebnisse erzeugt.` : msg;
    await db.update(scans).set({ status: "failed", phase: "Fehlgeschlagen", error: redact(reason), finishedAt: new Date() }).where(eq(scans.id, scan.id));
    await db.update(scanJobs).set({ state: "done" }).where(eq(scanJobs.id, claimed.jobId));
    console.error(`[dispatcher] Scan ${scan.id} fehlgeschlagen: ${redact(reason)}`);
  }
  return true;
}

async function loop() {
  console.log(`[dispatcher] gestartet, Runner: ${RUNNER_URL}`);
  let lastStaleCheck = 0;
  while (!stopping) {
    try {
      if (Date.now() - lastStaleCheck > 30_000) {
        const n = await failStaleScans(getDb());
        if (n) console.log(`[dispatcher] ${n} Scan(s) ohne Rückmeldung beendet`);
        lastStaleCheck = Date.now();
      }
      const didWork = await dispatchOnce();
      if (!didWork) await new Promise((r) => setTimeout(r, POLL_MS));
    } catch (e) {
      console.error("[dispatcher] Fehler:", (e as Error).message);
      await new Promise((r) => setTimeout(r, POLL_MS * 2));
    }
  }
}

for (const sig of ["SIGTERM", "SIGINT"] as const) process.on(sig, () => (stopping = true));
void loop();
