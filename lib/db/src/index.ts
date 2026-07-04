import { drizzle } from "drizzle-orm/node-postgres";
import pg from "pg";
import * as schema from "./schema";

const { Pool } = pg;

if (!process.env.DATABASE_URL) {
  throw new Error(
    "DATABASE_URL must be set. Did you forget to provision a database?",
  );
}

export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  max: 25,
  min: 5,
  idleTimeoutMillis: 30_000,
  connectionTimeoutMillis: 10_000,
  keepAlive: true,
  keepAliveInitialDelayMillis: 10_000,
  allowExitOnIdle: false,
});

// CRITICAL: node-postgres Pool emits "error" on any idle client whose connection
// is terminated by the backend (e.g. Neon/managed Postgres closing idle connections
// with "terminating connection due to administrator command"). Without a listener,
// Node treats this as an unhandled EventEmitter error and CRASHES THE ENTIRE PROCESS.
// This was silently killing the whole server every ~30-60 minutes in production,
// interrupting long-running crons (e.g. lead qualification) mid-batch every time.
pool.on("error", (err) => {
  console.error("[db] Idle pg client error (connection recycled by backend, pool recovers automatically):", err.message);
});

export const db = drizzle(pool, { schema });

export * from "./schema";
