// Direkter Testlauf des Runners gegen das lokale Testziel (ohne Web/DB).
import { runJob } from "../src/runner/pipeline";
import { randomUUID } from "node:crypto";
const mode = (process.argv[2] ?? "baseline") as "baseline" | "authenticated" | "active";
const spec = {
  jobId: randomUUID(), scanId: randomUUID(), mode, siteName: "Testziel", environment: "development",
  baseUrl: "https://127.0.0.1:8443/", scope: { hosts: ["127.0.0.1"], includePaths: ["/"], excludePaths: [] },
  limits: { maxDurationMinutes: 4, maxRequests: 400, requestsPerSecond: 10, maxDepth: 4, maxChildren: 20, threads: 2 },
  callbackUrl: "http://unused", callbackToken: "x".repeat(32), allowInvalidCerts: true,
  auth: mode === "authenticated" ? { roles: [{ label: "Admin-Test", kind: "header" as const, headerName: "Authorization", value: "Bearer tt-session-SuperGeheim-4711", verifyUrl: "https://127.0.0.1:8443/admin", logoutUrl: "https://127.0.0.1:8443/logout" }] } : undefined,
  active: mode === "active" ? { approvalId: randomUUID(), windowEnd: new Date(Date.now() + 3600e3).toISOString(), profile: "webaudit-safe" as const, allowWriteEffects: false } : undefined,
};
const ctrl = new AbortController();
await runJob(spec, async (e) => {
  if (e.type === "heartbeat") return;
  if (e.type === "results") {
    console.log(`RESULTS: ${e.findings.length} findings`);
    for (const f of e.findings) console.log(` - [${f.severity}/${f.kind}] ${f.title} :: ${f.ruleId} :: ${f.affectedUrl ?? ""} (+${f.otherUrls?.length ?? 0})`);
    for (const c of e.coverage) console.log(`   cov ${c.checkId} ${c.state} ${c.limitation ?? ""}`);
  } else console.log(JSON.stringify(e).slice(0, 400));
}, ctrl.signal);
