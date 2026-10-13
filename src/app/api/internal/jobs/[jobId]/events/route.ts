import { NextResponse } from "next/server";
import { getDb } from "@/lib/db";
import { verifyJobSignature } from "@/lib/security/crypto";
import { handleRunnerEvent } from "@/lib/scans/service";
import { isUuid } from "@/lib/auth/rbac";
import type { RunnerEvent } from "@/lib/jobs/spec";

export const dynamic = "force-dynamic";

/** Interner Callback-Endpunkt des Scan-Runners. Nur mit gültiger job-spezifischer HMAC-Signatur. */
export async function POST(req: Request, { params }: { params: Promise<{ jobId: string }> }) {
  const { jobId } = await params;
  if (!isUuid(jobId)) return NextResponse.json({ error: "not found" }, { status: 404 });
  const body = await req.text();
  if (body.length > 20_000_000) return NextResponse.json({ error: "too large" }, { status: 413 });
  const ts = req.headers.get("x-webaudit-ts") ?? "";
  const sig = req.headers.get("x-webaudit-sig") ?? "";
  if (!/^[0-9a-f]{64}$/.test(sig) || !verifyJobSignature(jobId, ts, body, sig)) {
    return NextResponse.json({ error: "invalid signature" }, { status: 401 });
  }
  let event: RunnerEvent;
  try {
    event = JSON.parse(body) as RunnerEvent;
  } catch {
    return NextResponse.json({ error: "invalid json" }, { status: 400 });
  }
  const r = await handleRunnerEvent(getDb(), jobId, event);
  return NextResponse.json({ cancel: r.cancel }, { status: r.status });
}
