"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";

type Status = { status: string; phase: string | null; progress: number; events: { level: string; message: string; createdAt: string }[] };

export function ScanProgress({ scanId, initial }: { scanId: string; initial: Status }) {
  const [s, setS] = useState(initial);
  const router = useRouter();
  useEffect(() => {
    if (!["queued", "running", "cancel_requested"].includes(s.status)) return;
    const t = setInterval(async () => {
      const r = await fetch(`/api/scans/${scanId}/status`, { cache: "no-store" });
      if (!r.ok) return;
      const j = (await r.json()) as Status;
      setS(j);
      if (!["queued", "running", "cancel_requested"].includes(j.status)) {
        clearInterval(t);
        router.refresh();
      }
    }, 2000);
    return () => clearInterval(t);
  }, [scanId, s.status, router]);
  return (
    <div className="space-y-2" aria-live="polite">
      <div className="flex justify-between text-sm"><span>{s.phase ?? "–"}</span><span>{s.progress}%</span></div>
      <div className="h-2 w-full rounded bg-slate-200"><div className="h-2 rounded bg-blue-700 transition-all" style={{ width: `${s.progress}%` }} /></div>
      {s.events.length ? (
        <ul className="max-h-48 space-y-1 overflow-auto text-xs text-slate-600">
          {s.events.map((e, i) => (
            <li key={i} className={e.level === "error" ? "text-red-700" : e.level === "warn" ? "text-amber-700" : ""}>{new Date(e.createdAt).toLocaleTimeString("de-CH")} – {e.message}</li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}

export function CopyButton({ text, label = "Kopieren" }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  return (
    <button
      type="button"
      className="btn-secondary text-xs"
      onClick={async () => {
        await navigator.clipboard.writeText(text);
        setDone(true);
        setTimeout(() => setDone(false), 2000);
      }}
    >
      {done ? "Kopiert" : label}
    </button>
  );
}
