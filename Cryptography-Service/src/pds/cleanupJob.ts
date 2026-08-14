import cron from "node-cron";
import { pgPool } from "./db";

// Hourly SEK cleanup, per requirement PDF p.14's schedule table: at hour H
// (UTC), delete the bucket that's now guaranteed to be 24h stale. The table
// there reads 00:00->23, 01:00->0, 02:00->1, ... i.e. bucket = (H + 23) % 24.
// Must use the same clock basis (UTC) as the bucket assignment in
// sekStore.ts's storeSek() — see currentHourBucketUTC() there.

export function bucketToDeleteForHour(currentHourUTC: number): number {
  return (currentHourUTC + 23) % 24;
}

export async function runCleanupOnce(currentHourUTC: number = new Date().getUTCHours()): Promise<number> {
  const bucketToDelete = bucketToDeleteForHour(currentHourUTC);
  const { rowCount } = await pgPool.query("DELETE FROM session_encryption_key WHERE expiration_bucket = $1", [
    bucketToDelete
  ]);
  console.log(`SEK cleanup: removed ${rowCount} row(s) from expiration_bucket ${bucketToDelete}`);
  return rowCount ?? 0;
}

export function startCleanupJob(): void {
  cron.schedule("0 * * * *", async () => {
    try {
      await runCleanupOnce();
    } catch (err) {
      console.error("SEK cleanup failed:", (err as Error).message);
    }
  });
  console.log("SEK cleanup job scheduled (hourly, UTC)");
}
