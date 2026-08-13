import { Pool } from "pg";

// Single shared Postgres pool, used by both request handlers (sekStore.ts)
// and the hourly cleanup job (cleanupJob.ts).
export const pgPool = new Pool({
  connectionString: process.env.DATABASE_URL ?? "postgres://pds:pds-poc-password@postgres:5432/pds"
});
