# Kong + Custom Authentication Service POC

This is a runnable local POC demonstrating a JWE pass-through authentication flow:

Client -> Kong -> Custom Authentication Service -> Account Service

with a real Keycloak instance as the identity provider.

## Architecture

```text
Client --JWE--> Kong --JWE--> Auth Service (stateless)
                                  |
                     1. Decrypt JWE (Auth Service holds the private key)
                                  |
                     2. Validate inner JWT signature LOCALLY
                        using cached Keycloak JWKS (fast, no Keycloak call)
                                  |
                     3. Only call Keycloak introspection if you need
                        a real-time revocation check (optional, cacheable)
                                  |
Kong <---------- claims (Kong caches per-token, keyed by the raw JWE)
     |
     | X-User-ID / X-User-Roles / X-User-Scopes / X-Auth-Authenticated
     v
Account Service
```

Kong never decrypts the JWE — it only ever hashes the ciphertext to form a
cache key. Only the Auth Service holds the JWE decryption private key. The
decrypted payload is a real access token issued and signed by Keycloak;
the Auth Service verifies its signature against a locally cached JWKS
(`jose.createRemoteJWKSet`) instead of calling Keycloak on every request.

Since Keycloak doesn't natively issue JWE-wrapped access tokens, a small
`client-simulator` CLI stands in for "the client": it logs into Keycloak,
fetches the Auth Service's published public encryption key, and wraps the
resulting JWT into a compact JWE.

## Why this pattern, and what it costs

### Pros and cons at a glance

**Pros**

- Claims are opaque to Kong end to end — the gateway's logs/tracing never
  see plaintext identity data, shrinking log-handling and compliance scope.
- No secret material on the gateway tier — Kong holds no decryption key and
  can't be leveraged to forge or read tokens if compromised.
- The common path is fast: JWT signature checks are local against a cached
  JWKS (no per-request Keycloak call), and Kong's claims cache skips the
  Auth Service round trip entirely on repeat requests.
- Revocation freshness is a dial, not a fixed cost — real-time introspection
  is opt-in per route, so only the requests that need it pay for it.
- All auth logic (decryption, verification, claims mapping) lives in one
  place — the Auth Service — instead of being duplicated across gateways.
- Extending roles/scopes or adding routes is config-only; Kong and Account
  Service never need to change since they only see the resulting headers.

**Cons**

- Slower on a cache miss than Kong validating a plain JWT itself — every
  miss pays an HTTP hop to the Auth Service plus JWE decryption on top of
  JWT verification.
- Someone now owns JWE key rotation as a real operational procedure; this
  POC's ephemeral, regenerate-on-restart key is a shortcut around that, not
  a solution to it.
- Kong loses the ability to make claim-based decisions at the edge (ACLs,
  rate limits keyed off JWT claims) — anything claim-based must happen in
  the Auth Service or downstream.
- Kong's claims cache is per-node, not distributed — scaling Kong out
  horizontally scales up first-miss load on the Auth Service too.
- More components to keep in sync (Kong plugin, Auth Service mapping code,
  Keycloak realm/protocol-mapper config) than a single-service check would
  need, and debugging a live failure means correlating across all three.
- An extra moving part — Keycloak — to run, patch, and back up, plus the
  client-side JWE-wrapping step this POC adds since Keycloak doesn't issue
  JWE-wrapped access tokens natively.

### Step-by-step breakdown

Walking through the four steps in the diagram above — what each one buys
you, and what it costs, across performance, maintainability, ease of
extension, ease of governance, and ease of operation.

#### 1. JWE decryption — Auth Service holds the key, Kong never decrypts

- **Performance:** Kong itself does zero crypto — it only hashes the
  ciphertext for its cache key. The RSA-OAEP + AES-GCM decrypt cost is paid
  once, in the Auth Service, only on a cache miss.
- **Governance:** claims are opaque to Kong's access logs and request
  tracing, so anything downstream of Kong's logging pipeline never
  sees plaintext identity data — smaller compliance/log-handling surface.
  The flip side: Kong can't make claim-based decisions either (no
  claim-aware ACL/rate-limiting at the gateway), since it never sees them.
- **Operate:** whoever holds the private key owns rotation. This POC's
  keypair is ephemeral and in-memory — regenerated on every Auth Service
  restart, which invalidates any JWE minted before the restart — precisely
  because a real rotation procedure (stage new public key → wait out old
  tokens → retire old private key) is a production concern this demo
  sidesteps rather than solves.
- **Maintain:** one service owns decryption end to end, so there's a single
  place to change if the encryption scheme (algorithm, key size) ever needs
  to move.

#### 2. Local JWT verification via cached Keycloak JWKS

- **Performance:** this is the main latency win in the whole design — the
  common path (`jose.createRemoteJWKSet`) never calls Keycloak at all; it
  verifies against a JWKS fetched once and cached.
- **Operate:** that cache (`cacheMaxAge: 600_000` here) means a Keycloak
  signing-key rotation doesn't propagate to the Auth Service instantly —
  there's a bounded window where a brand-new signing key wouldn't yet be
  trusted. Worth knowing before you tune the cache TTL.
- **Maintain:** `jose` handles fetch-and-cache for you, so this step adds
  almost no custom code to keep correct.
- **Extend:** supporting an additional Keycloak realm or a second IdP means
  wiring another JWKS URL + issuer check — a bounded, well-understood
  change, not a redesign.

#### 3. Optional, cacheable Keycloak introspection

- **Performance:** strictly opt-in — a route only pays the extra Keycloak
  round trip if it asks for real-time revocation via
  `X-Require-Revocation-Check`; everything else skips it entirely.
- **Governance:** this is the actual governance lever in the design — each
  route/team can decide, independently, how much revocation freshness it
  needs, instead of the whole system being locked into one answer.
- **Operate:** the moment a route turns this on, it takes on a hard runtime
  dependency on Keycloak's availability for that request (softened by the
  30s in-memory introspection cache, but not removed).
- **Extend:** turning stronger revocation checking on for a sensitive route
  is a config/header change, not new Auth Service code.

#### 4. Kong caches claims, keyed by the hashed JWE, TTL capped by token `exp`

- **Performance:** the other major win — once a token's claims are cached,
  repeat requests skip the Auth Service round trip (and therefore steps 1–3)
  entirely until the cache entry expires.
- **Operate:** the cache is an in-memory shared dict local to each Kong
  node, not distributed — so scaling Kong out horizontally doesn't share
  cache hits across replicas, and implicitly scales up first-miss traffic
  to the Auth Service in proportion to the number of nodes.
- **Governance:** the TTL is a governance-relevant knob — it bounds how
  long a request could be served against claims that predate a revocation.
  Failed/expired lookups are deliberately never cached, trading resilience
  against abusive traffic for not masking a since-revoked credential.
- **Maintain:** the caching logic is a single `min(cache_ttl_seconds,
  exp - now)` rule plus soft-fail-open on cache errors — small enough to
  read in one sitting.

## Requirements

- Docker
- Docker Compose

## Start

```bash
docker compose up --build
```

This brings up Keycloak, Kong, the Auth Service, and the Account Service.
`client-simulator` is not started automatically (it's a one-shot CLI, not a
long-running service — see below). Wait for Keycloak and Auth Service to
report healthy:

```bash
docker compose ps
```

Keycloak typically takes 20-40 seconds to become healthy on first start.

## Get a JWE test token

```bash
docker compose run --rm client-simulator demo-user
```

This logs into Keycloak as `demo-user` / `demo-pass`, encrypts the issued
access token into a JWE, and prints the JWE plus a ready-to-run curl
command, e.g.:

```bash
curl -H "Authorization: Bearer <jwe>" http://localhost:8000/api/accounts
```

Run the printed curl command. Expected HTTP 200 with account data
(`account.read` scope only).

For the admin user (with `account.write` scope):

```bash
docker compose run --rm client-simulator admin-user
```

## Test invalid/tampered token

Take a valid JWE from above and flip a character in it, then:

```bash
curl -H "Authorization: Bearer <tampered-jwe>" http://localhost:8000/api/accounts
```

Expected HTTP 401 — JWE decryption/authentication tag verification fails.

## Test expired token

Keycloak access tokens in this realm expire after 2 minutes
(`accessTokenLifespan` in `keycloak/realm-poc.json`, shortened from the
default 5 minutes for faster local testing). Wait past that, then re-run a
previously-printed curl command. Expected HTTP 401.

## Test claims caching

Kong caches successful validation results per-token (keyed by a hash of the
raw JWE) so repeat requests within the cache TTL (`cache_ttl_seconds`,
default 60s, capped further by the token's own `exp`) skip the Auth Service
round trip entirely.

```bash
curl -H "Authorization: Bearer <jwe>" http://localhost:8000/api/accounts
curl -H "Authorization: Bearer <jwe>" http://localhost:8000/api/accounts
docker compose logs auth-service --since 1m
```

You should see only one `/validate called (correlation_id=...)` line for the
pair of requests — the second request was served from Kong's shared-memory
cache without calling the Auth Service. Wait past the TTL and repeat to see
it call through again.

## Inspect Kong

Kong Admin API:

```bash
curl http://localhost:8001
```

## Stop

```bash
docker compose down
```

## Important production changes

This POC intentionally takes shortcuts for local runnability. For production:

1. Use TLS/mTLS between Kong and Custom Auth Service.
2. The Auth Service's JWE decryption keypair is generated fresh, in-memory,
   on every restart — any JWE encrypted before a restart becomes
   permanently undecryptable. Use a persisted, rotated key (KMS/HSM) instead.
3. The `client-simulator` uses a Resource Owner Password Credentials grant
   purely for local test-token minting. Real clients must use an
   authorization-code + PKCE flow — never ROPC — and should never handle
   raw user credentials directly.
4. Keycloak runs in `start-dev` mode with an in-memory H2 database and
   `sslRequired: none`. This is not production-safe — use a real database,
   TLS, and a hardened realm configuration.
5. Roles and scopes are both modeled as plain Keycloak realm roles
   (`customer`/`admin`/`account.read`/`account.write`), filtered by name in
   the Auth Service. A production setup should use dedicated OAuth2 scopes
   with proper client-scope protocol mappers instead.
6. Kong's claims cache is per-node, in-memory, and only caches successful
   validations (no negative/failure caching, to avoid masking a
   since-revoked credential behind a longer TTL than intended).
7. Do not trust client-supplied identity headers — the plugin explicitly
   clears them before setting trusted values.
8. Keep the Auth Service inaccessible from the Internet.
9. Add circuit-breaker behavior for Keycloak/Auth Service outages beyond
   the existing request timeout.
10. Add audit logging without logging credentials or raw tokens.
11. Keep business authorization in the owning microservice.

## Main architectural decision

Kong is the API security enforcement point and a dumb JWE pass-through — it
never decrypts.

The Custom Authentication Service owns authentication: JWE decryption,
local JWT/JWKS verification, and optional Keycloak introspection.

The microservice owns resource/business authorization.
