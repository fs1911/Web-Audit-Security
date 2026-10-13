import { drizzle, type PostgresJsDatabase } from "drizzle-orm/postgres-js";
import postgres from "postgres";
import * as schema from "./schema";

export type DB = PostgresJsDatabase<typeof schema>;

const globalForDb = globalThis as unknown as { __webauditDb?: DB; __webauditSql?: postgres.Sql };

export function getDb(): DB {
  if (!globalForDb.__webauditDb) {
    const url = process.env.DATABASE_URL;
    if (!url) throw new Error("DATABASE_URL ist nicht gesetzt.");
    const client = postgres(url, { max: Number(process.env.DATABASE_POOL_MAX ?? 10), prepare: false });
    globalForDb.__webauditSql = client;
    globalForDb.__webauditDb = drizzle(client, { schema });
  }
  return globalForDb.__webauditDb;
}

export async function closeDb(): Promise<void> {
  await globalForDb.__webauditSql?.end({ timeout: 5 });
  globalForDb.__webauditDb = undefined;
  globalForDb.__webauditSql = undefined;
}

export { schema };
