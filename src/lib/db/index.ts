import { drizzle, type PostgresJsDatabase } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import { getCloudflareContext } from "@opennextjs/cloudflare";
import * as schema from "./schema";

export type DB = PostgresJsDatabase<typeof schema>;

const globalForDb = globalThis as unknown as { __webauditDb?: DB; __webauditSql?: postgres.Sql; __webauditDbOverride?: DB };

/**
 * Lokal/Node: ein globaler Verbindungspool.
 * Cloudflare Worker (WEBAUDIT_RUNTIME=cloudflare): Verbindungen dürfen nicht über Requests
 * hinweg geteilt werden. Daher ein Client pro Request, Verbindungsdaten aus dem
 * Hyperdrive-Binding. Für den Cron-Dispatcher setzt der Worker-Einstieg einen Override.
 */
const perRequest = new WeakMap<object, DB>();

export function getDb(): DB {
  if (globalForDb.__webauditDbOverride) return globalForDb.__webauditDbOverride;
  if (process.env.WEBAUDIT_RUNTIME === "cloudflare") {
    const { env, ctx } = getCloudflareContext() as unknown as { env: { HYPERDRIVE?: { connectionString: string } }; ctx: object };
    if (!env.HYPERDRIVE) throw new Error("Hyperdrive-Binding HYPERDRIVE fehlt (wrangler.jsonc).");
    let db = perRequest.get(ctx);
    if (!db) {
      const client = postgres(env.HYPERDRIVE.connectionString, { max: 5, fetch_types: false, prepare: false });
      db = drizzle(client, { schema });
      perRequest.set(ctx, db);
    }
    return db;
  }
  if (!globalForDb.__webauditDb) {
    const url = process.env.DATABASE_URL;
    if (!url) throw new Error("DATABASE_URL ist nicht gesetzt.");
    const client = postgres(url, { max: Number(process.env.DATABASE_POOL_MAX ?? 10), prepare: false });
    globalForDb.__webauditSql = client;
    globalForDb.__webauditDb = drizzle(client, { schema });
  }
  return globalForDb.__webauditDb;
}

/** Für Hintergrundaufgaben ausserhalb eines Requests (Cloudflare-Cron): eigener, kurzlebiger Client. */
export async function withDbConnection<T>(connectionString: string, fn: () => Promise<T>): Promise<T> {
  const client = postgres(connectionString, { max: 2, fetch_types: false, prepare: false });
  globalForDb.__webauditDbOverride = drizzle(client, { schema });
  try {
    return await fn();
  } finally {
    globalForDb.__webauditDbOverride = undefined;
    await client.end({ timeout: 5 });
  }
}

export async function closeDb(): Promise<void> {
  await globalForDb.__webauditSql?.end({ timeout: 5 });
  globalForDb.__webauditDb = undefined;
  globalForDb.__webauditSql = undefined;
}

export { schema };
