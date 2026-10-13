import fs from "node:fs/promises";
import path from "node:path";
import { getCloudflareContext } from "@opennextjs/cloudflare";

/**
 * Privater Objektspeicher für Berichte. Kein öffentlicher Zugriff: Downloads laufen
 * ausschliesslich über die App mit Berechtigungsprüfung.
 * - "fs": lokales Verzeichnis (Entwicklung)
 * - "s3": S3-kompatibel (Cloudflare R2), signiert mit SigV4 über aws4fetch
 * - "r2": R2-Binding im Cloudflare Worker (keine Zugangsschlüssel nötig)
 */
export interface ObjectStore {
  put(key: string, data: Uint8Array, contentType: string): Promise<void>;
  get(key: string): Promise<Uint8Array>;
  delete(key: string): Promise<void>;
}

function safeKey(key: string): string {
  if (!/^[a-zA-Z0-9/_.-]+$/.test(key) || key.includes("..")) throw new Error("Ungültiger Objektschlüssel");
  return key;
}

class FsStore implements ObjectStore {
  constructor(private readonly root: string) {}
  private p(key: string) {
    return path.join(this.root, safeKey(key));
  }
  async put(key: string, data: Uint8Array) {
    await fs.mkdir(path.dirname(this.p(key)), { recursive: true, mode: 0o700 });
    await fs.writeFile(this.p(key), data, { mode: 0o600 });
  }
  async get(key: string) {
    return new Uint8Array(await fs.readFile(this.p(key)));
  }
  async delete(key: string) {
    await fs.rm(this.p(key), { force: true });
  }
}

class S3Store implements ObjectStore {
  constructor(
    private readonly endpoint: string,
    private readonly bucket: string,
    private readonly accessKeyId: string,
    private readonly secretAccessKey: string,
  ) {}
  private async client() {
    const { AwsClient } = await import("aws4fetch");
    return new AwsClient({ accessKeyId: this.accessKeyId, secretAccessKey: this.secretAccessKey, service: "s3", region: "auto" });
  }
  private url(key: string) {
    return `${this.endpoint.replace(/\/$/, "")}/${this.bucket}/${safeKey(key)}`;
  }
  async put(key: string, data: Uint8Array, contentType: string) {
    const c = await this.client();
    const r = await c.fetch(this.url(key), { method: "PUT", body: data as unknown as BodyInit, headers: { "content-type": contentType } });
    if (!r.ok) throw new Error(`Objektspeicher: Upload fehlgeschlagen (${r.status})`);
  }
  async get(key: string) {
    const c = await this.client();
    const r = await c.fetch(this.url(key));
    if (!r.ok) throw new Error(`Objektspeicher: Abruf fehlgeschlagen (${r.status})`);
    return new Uint8Array(await r.arrayBuffer());
  }
  async delete(key: string) {
    const c = await this.client();
    await c.fetch(this.url(key), { method: "DELETE" });
  }
}

type R2BucketLike = {
  put(key: string, value: Uint8Array, opts?: { httpMetadata?: { contentType?: string } }): Promise<unknown>;
  get(key: string): Promise<{ arrayBuffer(): Promise<ArrayBuffer> } | null>;
  delete(key: string): Promise<void>;
};

class R2BindingStore implements ObjectStore {
  private bucket(): R2BucketLike {
    const env = getCloudflareContext().env as unknown as { REPORTS?: R2BucketLike };
    if (!env.REPORTS) throw new Error("R2-Binding REPORTS fehlt (wrangler.jsonc).");
    return env.REPORTS;
  }
  async put(key: string, data: Uint8Array, contentType: string) {
    await this.bucket().put(safeKey(key), data, { httpMetadata: { contentType } });
  }
  async get(key: string) {
    const o = await this.bucket().get(safeKey(key));
    if (!o) throw new Error("Objektspeicher: Objekt nicht gefunden");
    return new Uint8Array(await o.arrayBuffer());
  }
  async delete(key: string) {
    await this.bucket().delete(safeKey(key));
  }
}

export function getStore(): ObjectStore {
  const driver = process.env.STORAGE_DRIVER ?? "fs";
  if (driver === "r2") return new R2BindingStore();
  if (driver === "s3") {
    const { S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY } = process.env;
    if (!S3_ENDPOINT || !S3_BUCKET || !S3_ACCESS_KEY_ID || !S3_SECRET_ACCESS_KEY) {
      throw new Error("STORAGE_DRIVER=s3 gesetzt, aber S3_ENDPOINT/S3_BUCKET/S3_ACCESS_KEY_ID/S3_SECRET_ACCESS_KEY fehlen.");
    }
    return new S3Store(S3_ENDPOINT, S3_BUCKET, S3_ACCESS_KEY_ID, S3_SECRET_ACCESS_KEY);
  }
  return new FsStore(path.resolve(process.env.STORAGE_DIR ?? "./var/storage"));
}
