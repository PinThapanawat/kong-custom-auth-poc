# Load test results

Target: `Client -> Kong -> Auth Service -> Account Service` via the JWE
pass-through flow described in the main [README](../README.md).

**Environment:** local `docker compose` stack (4 CPUs / ~7.7GB allocated to
Docker Desktop), all requests from the host against `http://localhost:8000`.
Tool: [`hey`](https://github.com/rakyll/hey) for the runs below; an
equivalent [`k6`](https://k6.io) script is provided at
[`k6-script.js`](./k6-script.js) for repeat/CI runs with richer percentile
reporting.

**Token:** a single JWE for Keycloak's `demo-user`, reused across each
run's requests (minted via `docker compose run --rm client-simulator
demo-user`). `accessTokenLifespan` was temporarily extended in
`keycloak/realm-poc.json` for the longer runs so the token wouldn't expire
mid-test, then reverted afterward.

## Summary

| # | Scenario | Target | Achieved | p50 | p95 | p99 | Errors |
|---|---|---|---|---|---|---|---|
| 1 | Cache **enabled** (default config), c=100 | 1000 rps | 998/s | 13ms | 24ms | 32ms | 0% |
| 2 | Cache **disabled** (every request = full JWE decrypt + JWT verify), c=100 | 1000 rps | 974/s | 87ms | 117ms | 166ms | 0% |
| 3 | Cache **disabled**, pushed 2x, c=200 | 2000 rps | 1113/s (capped) | 128ms | 142ms | ~3.0s | 1.1% (503) |
| 4 | Cache **enabled** (default config), **c=1000, 10-minute soak** | 1000 rps | *(in progress — see below)* | | | | |

**Takeaway:** with Kong's claims cache doing its job (the shipped, default
configuration), 1000 rps is trivial — sub-15ms p50, zero errors, and
`auth-service` barely registers any CPU load. The real ceiling is the
cache-**miss** path: a single `auth-service` replica (single Node process)
saturates around **~1000-1100 req/s** doing JWE decryption + JWT
verification on every request (confirmed via `docker stats`: `auth-service`
pegged at 94% CPU while `kong`, `account-service`, and `keycloak` all had
slack). Pushing past that doesn't crash anything, but requests start
queueing behind Kong's `timeout_ms: 3000` and a small percentage start
failing with `503`.

## Test 1 — Cache enabled, 1000 rps target, concurrency 100

```
hey -z 15s -c 100 -q 10 -H "Authorization: Bearer <jwe>" http://localhost:8000/api/accounts
```

- Requests/sec: **998.45**
- Latency: p50 12.9ms / p75 17.7ms / p90 21.3ms / p95 24.1ms / p99 31.9ms
- Status codes: `200` x 15000 (0 errors)

## Test 2 — Cache disabled, 1000 rps target, concurrency 100

`kong/kong.yml`'s `custom-auth` plugin temporarily set to `enable_cache: false`, Kong rebuilt/restarted, so **every** request pays the full JWE-decrypt + JWKS-verified-JWT path in `auth-service`.

```
hey -z 15s -c 100 -q 10 -H "Authorization: Bearer <jwe>" http://localhost:8000/api/accounts
```

- Requests/sec: **974.22**
- Latency: p50 87.5ms / p75 95.2ms / p90 106.7ms / p95 117.4ms / p99 166.3ms
- Status codes: `200` x 14712 (0 errors)
- `docker stats` mid-run: `auth-service` **94.16% CPU**, `kong` 19.4%, `account-service` 15.9%, `keycloak` 0.2% (untouched — JWKS served from `auth-service`'s local cache, no per-request Keycloak call)

## Test 3 — Cache disabled, pushed to 2000 rps target, concurrency 200

Same cache-disabled config as Test 2, target rate doubled to find the breaking point (fresh token minted immediately before the run, to isolate load-induced failures from token expiry).

```
hey -z 8s -c 200 -q 10 -H "Authorization: Bearer <jwe>" http://localhost:8000/api/accounts
```

- Requests/sec: **1112.99** (couldn't exceed ~1100 — this is the real ceiling, not the 2000 target)
- Latency: p50 128.1ms / p75 135.2ms / p90 139.4ms / p95 141.9ms / **p99 ~3004ms**
- Status codes: `200` x 9000, `503` x 100 (**1.1% error rate**)
- The p99 latency (~3.0s) lines up exactly with the plugin's `timeout_ms: 3000` — once the queue backs up past the cache-miss ceiling, Kong's upstream call to `auth-service` times out and returns `503`.

## Test 4 — Cache enabled, concurrency 1000, ~1000 rps target, 10-minute soak

Sustained soak test at the shipped (cache-enabled) configuration, with
higher concurrency than Test 1 to check stability over a longer window
(GC pressure, event-loop lag creep, connection handling under 1000
concurrent clients) rather than just a short burst.

```
hey -z 10m -c 1000 -q 1 -H "Authorization: Bearer <jwe>" http://localhost:8000/api/accounts
```

15-second dry run at the same settings (sanity check before committing to
the full 10 minutes):

- Requests/sec: 988.30
- Latency: p50 99.9ms / p75 141.9ms / p90 169.0ms / p95 183.8ms / p99 328.3ms
- Status codes: `200` x 15000 (0 errors)
- Note: latency here is higher than Test 1 despite `auth-service` CPU staying near-idle (cache hits) — the difference is connection/scheduling overhead from holding 1000 concurrent connections open rather than 100, not auth cost.

Full 10-minute run (`accessTokenLifespan` temporarily extended to 900s in
`keycloak/realm-poc.json` so the token stayed valid for the whole run,
reverted to 120s afterward):

- **600,000 requests over 600.2s → 999.67 req/s achieved — essentially
  exactly the 1000 rps target.**
- Latency: p50 121.6ms / p75 174.2ms / p90 254.2ms / p95 310.2ms / p99 377.1ms
- Status codes: `200` x 600,000 — **zero errors across the entire 10-minute
  run.**
- Resource stability (sampled every 45s throughout): `auth-service` stayed
  flat at ~64MB memory and ~0% CPU the whole time (cache absorbing nearly
  all traffic — only the periodic ~60s-TTL cache-refresh calls reach it);
  `kong` settled at ~580MB / ~14% CPU after an initial ramp and stayed flat;
  `account-service` and `keycloak` were both steady and low. No memory
  growth or CPU creep over the full run — no sign of a leak or event-loop
  degradation under sustained load.

**Conclusion for this scenario: the default configuration comfortably
sustains 1000 rps at 1000 concurrent connections for at least 10 minutes,
with zero errors and flat resource usage.** Latency is higher than the
lower-concurrency Test 1 (p50 122ms vs 13ms) — that gap is connection/
scheduling overhead from holding 1000 concurrent connections open, not
auth cost (`auth-service` CPU stayed near-idle throughout).

## Reproducing with k6

```bash
docker compose run --rm client-simulator demo-user   # mint a token, copy the JWE

k6 run -e TOKEN=<jwe> -e RATE=1000 -e VUS=1000 -e DURATION=10m loadtest/k6-script.js

# or via Docker, no local k6 install needed, addressing Kong on the compose network:
docker run --rm -i --network kong-custom-auth-poc_default \
  -e TOKEN=<jwe> -e BASE_URL=http://kong:8000/api/accounts \
  -e RATE=1000 -e VUS=1000 -e DURATION=10m \
  -v "$PWD/loadtest:/scripts" -w /scripts \
  grafana/k6 run --summary-export=results-summary.json k6-script.js
```

k6's `constant-arrival-rate` executor targets the rate directly (unlike
`hey`'s per-worker `-q`), and its default summary reports full percentile
breakdowns plus pass/fail against the thresholds defined in the script
(`http_req_failed rate < 1%`, `p(95) < 500ms`, `p(99) < 1000ms`).

## Practical implication

Whether 1000 rps is "safe" depends entirely on your real cache-hit ratio.
If most traffic is repeat requests within the cache TTL (the case this
design targets), you're nowhere near the ceiling. If traffic is closer to
100% unique tokens per request, a single `auth-service` replica is already
at its limit at 1000 rps — scale it horizontally (it's stateless) or raise
Node's `UV_THREADPOOL_SIZE` (RSA operations ride the libuv threadpool,
default size 4, which lines up closely with the observed ~1000/s ceiling).
