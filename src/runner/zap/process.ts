import { spawn, type ChildProcess } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import crypto from "node:crypto";
import net from "node:net";

/**
 * Startet eine isolierte ZAP-Instanz pro Scan (eigenes Home-Verzeichnis, eigener API-Key,
 * nur auf 127.0.0.1). Die Proxy-Umgebungsvariablen des Hosts werden entfernt, damit ZAP
 * ausschliesslich über den Egress-Guard-Proxy nach aussen gelangt.
 */
export type ZapInstance = { baseUrl: string; apiKey: string; proc: ChildProcess; home: string; version?: string; stop: () => Promise<void> };

/** Alle laufenden ZAP-Prozessgruppen; werden beim Beenden des Runners zwingend gestoppt. */
const liveZapGroups = new Set<number>();
process.on("exit", () => {
  for (const pid of liveZapGroups) {
    try {
      process.kill(-pid, "SIGKILL");
    } catch {
      /* bereits beendet */
    }
  }
});

export function zapInstallDir(): string | null {
  const dir = process.env.ZAP_HOME_DIR ?? "/opt/zap";
  try {
    const jar = fs.readdirSync(dir).find((f) => /^zap-[\d.]+\.jar$/.test(f));
    return jar ? dir : null;
  } catch {
    return null;
  }
}

export function zapAvailability(): { available: true; dir: string; jar: string } | { available: false; reason: string } {
  const dir = zapInstallDir();
  if (!dir) return { available: false, reason: `OWASP ZAP nicht gefunden (ZAP_HOME_DIR=${process.env.ZAP_HOME_DIR ?? "/opt/zap"}). Installation: npm run zap:install` };
  const jar = fs.readdirSync(dir).find((f) => /^zap-[\d.]+\.jar$/.test(f))!;
  return { available: true, dir, jar };
}

async function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const s = net.createServer();
    s.listen(0, "127.0.0.1", () => {
      const p = (s.address() as net.AddressInfo).port;
      s.close(() => resolve(p));
    });
    s.on("error", reject);
  });
}

export async function startZap(opts: { memoryMb?: number; startTimeoutMs?: number; signal?: AbortSignal } = {}): Promise<ZapInstance> {
  const avail = zapAvailability();
  if (!avail.available) throw new Error(avail.reason);
  const port = await freePort();
  const apiKey = crypto.randomBytes(24).toString("hex");
  const home = fs.mkdtempSync(path.join(os.tmpdir(), "webaudit-zap-"));
  const env = { PATH: process.env.PATH, HOME: home, LANG: "C.UTF-8" } as unknown as NodeJS.ProcessEnv;
  const args = [
    `-Xmx${opts.memoryMb ?? 1536}m`,
    "-jar",
    path.join(avail.dir, avail.jar),
    "-daemon",
    "-host",
    "127.0.0.1",
    "-port",
    String(port),
    "-dir",
    home,
    "-silent",
    "-notel",
    "-config",
    `api.key=${apiKey}`,
    "-config",
    "api.addrs.addr.name=127.0.0.1",
    "-config",
    "api.addrs.addr.regex=false",
    "-config",
    "database.recoverylog=false",
  ];
  const proc = spawn("java", args, { cwd: avail.dir, env, stdio: ["ignore", "pipe", "pipe"], detached: true });
  if (proc.pid) liveZapGroups.add(proc.pid);
  proc.on("exit", () => proc.pid && liveZapGroups.delete(proc.pid));
  let output = "";
  const collect = (d: Buffer) => {
    output = (output + d.toString()).slice(-8000);
  };
  proc.stdout?.on("data", collect);
  proc.stderr?.on("data", collect);
  const baseUrl = `http://127.0.0.1:${port}`;
  const stop = async () => {
    try {
      await fetch(`${baseUrl}/JSON/core/action/shutdown/`, { headers: { "X-ZAP-API-Key": apiKey }, signal: AbortSignal.timeout(3000) });
    } catch {
      /* ignorieren */
    }
    await new Promise((r) => setTimeout(r, 1500));
    if (proc.exitCode === null && proc.pid) {
      try {
        process.kill(-proc.pid, "SIGKILL");
      } catch {
        /* bereits beendet */
      }
    }
    if (proc.pid) liveZapGroups.delete(proc.pid);
    fs.rmSync(home, { recursive: true, force: true });
  };
  const deadline = Date.now() + (opts.startTimeoutMs ?? 120_000);
  while (Date.now() < deadline) {
    if (opts.signal?.aborted) {
      await stop();
      throw new Error("Abgebrochen");
    }
    if (proc.exitCode !== null) throw new Error(`ZAP wurde unerwartet beendet: ${output.slice(-500)}`);
    try {
      const r = await fetch(`${baseUrl}/JSON/core/view/version/`, { headers: { "X-ZAP-API-Key": apiKey }, signal: AbortSignal.timeout(2000) });
      if (r.ok) {
        const j = (await r.json()) as { version: string };
        return { baseUrl, apiKey, proc, home, version: j.version, stop };
      }
    } catch {
      /* noch nicht bereit */
    }
    await new Promise((r) => setTimeout(r, 1000));
  }
  await stop();
  throw new Error("ZAP ist nicht rechtzeitig gestartet");
}
