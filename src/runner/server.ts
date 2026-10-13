import http from "node:http";
import { z } from "zod";
import { runJob } from "./pipeline";
import { signBody, safeEqual } from "../lib/security/crypto";
import type { JobSpec, RunnerEvent } from "../lib/jobs/spec";
import { zapAvailability } from "./zap/process";
import { repoAdapterAvailability } from "./repo/repo";

/**
 * Scan-Runner: separater Prozess/Container. Nimmt Jobs nur mit gemeinsamem Secret an
 * (RUNNER_SHARED_SECRET), hält keine Datenbankzugangsdaten und meldet Ergebnisse über
 * HMAC-signierte Callbacks mit job-spezifischem Token.
 */

const PORT = Number(process.env.RUNNER_PORT ?? 8787);
const HOST = process.env.RUNNER_HOST ?? "127.0.0.1";
const MAX_CONCURRENT = Number(process.env.RUNNER_MAX_CONCURRENT ?? 1);
const SHARED = process.env.RUNNER_SHARED_SECRET ?? "";

const running = new Map<string, AbortController>();

const SpecSchema = z.object({
  jobId: z.string().uuid(),
  scanId: z.string().uuid(),
  mode: z.enum(["baseline", "authenticated", "active", "repository"]),
  siteName: z.string(),
  environment: z.string(),
  baseUrl: z.string(),
  scope: z.object({ hosts: z.array(z.string()).min(1), includePaths: z.array(z.string()), excludePaths: z.array(z.string()) }),
  limits: z.object({ maxDurationMinutes: z.number(), maxRequests: z.number(), requestsPerSecond: z.number(), maxDepth: z.number(), maxChildren: z.number(), threads: z.number() }),
  callbackUrl: z.string().url(),
  callbackToken: z.string().min(20),
  auth: z.object({ roles: z.array(z.object({ label: z.string(), kind: z.enum(["header", "cookie"]), headerName: z.string().optional(), value: z.string(), verifyUrl: z.string().optional(), logoutUrl: z.string().optional() })) }).optional(),
  repo: z.object({ url: z.string(), token: z.string().optional(), ref: z.string().optional() }).optional(),
  active: z.object({ approvalId: z.string(), windowEnd: z.string(), profile: z.literal("webaudit-safe"), allowWriteEffects: z.boolean() }).optional(),
  allowInvalidCerts: z.boolean().optional(),
});

function makeEmitter(spec: JobSpec, ctrl: AbortController) {
  return async (event: RunnerEvent) => {
    const body = JSON.stringify(event);
    for (let attempt = 0; attempt < 4; attempt++) {
      try {
        const ts = String(Date.now());
        const res = await fetch(spec.callbackUrl, {
          method: "POST",
          headers: { "content-type": "application/json", "x-webaudit-ts": ts, "x-webaudit-sig": signBody(spec.callbackToken, ts, body) },
          body,
          signal: AbortSignal.timeout(30_000),
        });
        if (res.ok) {
          const j = (await res.json().catch(() => ({}))) as { cancel?: boolean };
          if (j.cancel && !ctrl.signal.aborted) {
            console.log(`[runner] Abbruch für Job ${spec.jobId} angefordert`);
            ctrl.abort();
          }
          return;
        }
        if (res.status === 409 || res.status === 404) {
          // Scan existiert nicht mehr bzw. ist abgeschlossen → abbrechen
          ctrl.abort();
          return;
        }
      } catch {
        /* erneut versuchen */
      }
      await new Promise((r) => setTimeout(r, 1000 * 2 ** attempt));
    }
    console.error(`[runner] Callback für Job ${spec.jobId} dauerhaft fehlgeschlagen (${event.type})`);
  };
}

async function readBody(req: http.IncomingMessage, max = 1_000_000): Promise<string> {
  let size = 0;
  const chunks: Buffer[] = [];
  for await (const c of req) {
    size += (c as Buffer).length;
    if (size > max) throw new Error("Body zu gross");
    chunks.push(c as Buffer);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function authorized(req: http.IncomingMessage): boolean {
  const h = req.headers.authorization ?? "";
  return SHARED.length >= 32 && h.startsWith("Bearer ") && safeEqual(h.slice(7), SHARED);
}

const server = http.createServer(async (req, res) => {
  const send = (status: number, body: unknown) => {
    res.writeHead(status, { "content-type": "application/json" });
    res.end(JSON.stringify(body));
  };
  try {
    if (req.method === "GET" && req.url === "/health") {
      const zap = zapAvailability();
      const repo = await repoAdapterAvailability();
      return send(200, { ok: true, running: running.size, maxConcurrent: MAX_CONCURRENT, zap: zap.available ? { available: true } : zap, repoAdapters: repo.map(({ path: _p, ...r }) => r) });
    }
    if (!authorized(req)) return send(401, { error: "unauthorized" });
    if (req.method === "POST" && req.url === "/jobs") {
      if (running.size >= MAX_CONCURRENT) return send(429, { error: "Runner ausgelastet" });
      const parsed = SpecSchema.safeParse(JSON.parse(await readBody(req)));
      if (!parsed.success) return send(400, { error: "Ungültige Job-Spezifikation" });
      const spec = parsed.data as JobSpec;
      if (running.has(spec.jobId)) return send(409, { error: "Job läuft bereits" });
      const ctrl = new AbortController();
      running.set(spec.jobId, ctrl);
      const emit = makeEmitter(spec, ctrl);
      const hb = setInterval(() => void emit({ type: "heartbeat" }), 5000);
      console.log(`[runner] Job ${spec.jobId} (${spec.mode}) gestartet`);
      void runJob(spec, emit, ctrl.signal)
        .catch(async (e) => emit({ type: "failed", error: `Interner Runner-Fehler: ${(e as Error).message}` }))
        .finally(() => {
          clearInterval(hb);
          running.delete(spec.jobId);
          console.log(`[runner] Job ${spec.jobId} beendet`);
        });
      return send(202, { accepted: true });
    }
    const cancel = req.url?.match(/^\/jobs\/([0-9a-f-]{36})\/cancel$/);
    if (req.method === "POST" && cancel) {
      const ctrl = running.get(cancel[1]!);
      if (!ctrl) return send(404, { error: "Job nicht aktiv" });
      ctrl.abort();
      return send(200, { cancelled: true });
    }
    send(404, { error: "not found" });
  } catch (e) {
    send(500, { error: "Interner Fehler" });
    console.error("[runner]", (e as Error).message);
  }
});

if (SHARED.length < 32) {
  console.error("RUNNER_SHARED_SECRET fehlt oder ist kürzer als 32 Zeichen – Runner startet nicht.");
  process.exit(1);
}
server.listen(PORT, HOST, () => console.log(`[runner] hört auf ${HOST}:${PORT} (max. ${MAX_CONCURRENT} parallele Jobs)`));
for (const sig of ["SIGTERM", "SIGINT"] as const) {
  process.on(sig, () => {
    for (const c of running.values()) c.abort();
    setTimeout(() => process.exit(0), 3000);
  });
}
