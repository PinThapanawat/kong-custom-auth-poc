import Redis from "ioredis";

// Bounded retries so a mid-request Redis outage fails fast into the
// Postgres fallback path (sekStore.ts) instead of hanging the request.
export const redis = new Redis(process.env.REDIS_URL ?? "redis://redis:6379", {
  maxRetriesPerRequest: 1,
  lazyConnect: false
});

redis.on("error", (err) => {
  console.warn("Redis client error:", err.message);
});
