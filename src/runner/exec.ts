import { spawn } from "node:child_process";

/**
 * Prozessausführung OHNE Shell, mit festem Argument-Array, Zeitlimit und Abbruch.
 * Nutzereingaben werden nie als Shell-String interpretiert.
 */
export type ExecResult = { code: number | null; stdout: string; stderr: string; timedOut: boolean };

export function execFileSafe(
  cmd: string,
  args: string[],
  opts: { cwd?: string; env?: Record<string, string | undefined>; timeoutMs?: number; signal?: AbortSignal; maxOutputBytes?: number } = {},
): Promise<ExecResult> {
  return new Promise((resolve, reject) => {
    const env = (opts.env ?? { PATH: process.env.PATH }) as NodeJS.ProcessEnv;
    const child = spawn(cmd, args, { cwd: opts.cwd, env, shell: false, detached: true, stdio: ["ignore", "pipe", "pipe"] });
    const max = opts.maxOutputBytes ?? 50 * 1024 * 1024;
    let stdout = "";
    let stderr = "";
    let timedOut = false;
    child.stdout.on("data", (d: Buffer) => {
      if (stdout.length < max) stdout += d.toString();
    });
    child.stderr.on("data", (d: Buffer) => {
      if (stderr.length < 100_000) stderr += d.toString();
    });
    const kill = () => {
      if (child.pid && child.exitCode === null) {
        try {
          process.kill(-child.pid, "SIGKILL");
        } catch {
          /* bereits beendet */
        }
      }
    };
    const timer = setTimeout(() => {
      timedOut = true;
      kill();
    }, opts.timeoutMs ?? 10 * 60_000);
    opts.signal?.addEventListener("abort", kill, { once: true });
    child.on("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve({ code, stdout, stderr, timedOut });
    });
  });
}

export async function which(cmd: string): Promise<string | null> {
  const dirs = (process.env.PATH ?? "").split(":");
  const fs = await import("node:fs");
  for (const d of dirs) {
    const p = `${d}/${cmd}`;
    try {
      fs.accessSync(p, fs.constants.X_OK);
      return p;
    } catch {
      /* weiter */
    }
  }
  return null;
}
