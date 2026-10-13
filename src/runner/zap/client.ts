/** Minimaler, typisierter Client für die ZAP-REST-API (nur 127.0.0.1). */
export class ZapClient {
  constructor(
    private readonly baseUrl: string,
    private readonly apiKey: string,
  ) {}

  async call<T = Record<string, unknown>>(component: string, type: "view" | "action", name: string, params: Record<string, string | number | boolean> = {}): Promise<T> {
    const qs = new URLSearchParams(Object.entries(params).map(([k, v]) => [k, String(v)]));
    const res = await fetch(`${this.baseUrl}/JSON/${component}/${type}/${name}/?${qs}`, {
      headers: { "X-ZAP-API-Key": this.apiKey },
      signal: AbortSignal.timeout(60_000),
    });
    const body = (await res.json().catch(() => ({}))) as T & { code?: string; message?: string };
    if (!res.ok) throw new Error(`ZAP-API ${component}/${name} fehlgeschlagen: ${body.code ?? res.status} ${body.message ?? ""}`);
    return body;
  }
}

export type ZapAlert = {
  id: string;
  pluginId: string;
  alertRef?: string;
  alert: string;
  name: string;
  risk: "High" | "Medium" | "Low" | "Informational";
  confidence: "High" | "Medium" | "Low" | "Confirmed" | "False Positive";
  url: string;
  method: string;
  param: string;
  attack: string;
  evidence: string;
  otherinfo: string;
  description: string;
  solution: string;
  reference: string;
  cweid: string;
  wascid: string;
  sourceid: string;
  tags?: Record<string, string>;
  messageId?: string;
};
