// Load test for Client -> Kong -> Auth Service -> Account Service.
//
// Kong's claims cache (enable_cache / cache_ttl_seconds in kong.yml) is NOT
// controllable per-request from here — it's a plugin config, so to test the
// cache-disabled/worst-case path, edit kong/kong.yml (set enable_cache: false
// on the custom-auth plugin), rebuild+restart Kong, run this script, then
// revert.
//
// Get a token first:
//   docker compose run --rm client-simulator demo-user
//
// Run against the host-published Kong port:
//   k6 run -e TOKEN=<jwe> loadtest/k6-script.js
//
// Or via the official k6 Docker image, attached to the compose network so
// you can address services by their compose hostnames:
//   docker run --rm -i --network kong-custom-auth-poc_default \
//     -e TOKEN=<jwe> -e BASE_URL=http://kong:8000/api/accounts \
//     -v "$PWD/loadtest:/scripts" -w /scripts \
//     grafana/k6 run --summary-export=results-summary.json k6-script.js
//
// Override RATE / DURATION / VUS via -e to match whatever scenario you're
// after, e.g. -e RATE=1000 -e VUS=1000 -e DURATION=10m.

import http from "k6/http";
import { check } from "k6";

const BASE_URL = __ENV.BASE_URL || "http://localhost:8000/api/accounts";
const TOKEN = __ENV.TOKEN;
const RATE = Number(__ENV.RATE || 1000); // target requests/sec
const DURATION = __ENV.DURATION || "10m";
const VUS = Number(__ENV.VUS || 1000); // concurrency (max/pre-allocated VUs)

if (!TOKEN) {
  throw new Error(
    "Set TOKEN to a valid JWE. Mint one with: docker compose run --rm client-simulator demo-user"
  );
}

export const options = {
  scenarios: {
    constant_rps: {
      executor: "constant-arrival-rate",
      rate: RATE,
      timeUnit: "1s",
      duration: DURATION,
      preAllocatedVUs: VUS,
      maxVUs: VUS,
    },
  },
  thresholds: {
    http_req_failed: ["rate<0.01"],
    http_req_duration: ["p(95)<500", "p(99)<1000"],
  },
};

export default function () {
  const res = http.get(BASE_URL, {
    headers: { Authorization: `Bearer ${TOKEN}` },
  });

  check(res, {
    "status is 200": (r) => r.status === 200,
  });
}
