# Kong + Payload Decryptor Service POC

This is a runnable local POC implementing the "Payload Decryptor Service"
(PDS) spec in `requirement /Decryption-130826-131559.pdf`: every
request/response body between a mobile client and the backend BFF APIs is
signed (ECDSA P-256) and JWE-encrypted, with a real Keycloak instance as the
identity provider, Vault holding the PDS's key material, and Postgres/Redis
backing per-session encryption keys.

```text
Client -> Kong -> auth-service (the PDS) [-> Keycloak | -> account-service]
```

## Architecture

```text
Category 1 (device enrollment, session acquiring) — thin pass-through:

  Device --JWE(signed envelope)--> Kong --(routed, no crypto)--> auth-service (PDS)
                                                                       |
                                                     verify deviceJwt, decrypt JWE,
                                                     verify envelope signature,
                                                     Keycloak ROPC login,
                                                     issue sessionJwt + SEK,
                                                     store in Postgres (primary) /
                                                     Redis (4h cache)
                                                                       |
                                                                       v
                                                              back to Device

Category 2/3 (/pds/bff/*) — Kong's custom-auth plugin brokers the call:

  Device --JWE(signed envelope)--> Kong (custom-auth plugin)
                                        |
                                        | 1. POST /pds/internal/verify -----> auth-service (PDS)
                                        |                                     decrypt, verify sessionJwt +
                                        |                                     SEK + envelope signature
                                        | <---- outcome + plaintext + X-User-* headers
                                        |
                                        | 2. plaintext request -------------> account-service
                                        | <---- plaintext response            (zero crypto code)
                                        |
                                        | 3. POST /pds/internal/encrypt-response -> auth-service (PDS)
                                        | <---- encrypted, signed reply
                                        v
                                     Device
```

Kong is a pure pass-through for Category 1 (`kong/kong.yml`'s
`device-enrollment`, `session-acquiring`, and `pds-jwks` routes) — it never
decrypts anything there. For Category 2/3 (`pds-bff` route), Kong's
`custom-auth` plugin (`kong/plugins/custom-auth/handler.lua`) actively
checks with the PDS that auth is complete, then makes the call to
`account-service` itself and asks the PDS to encrypt the reply — Kong still
never holds a SEK or any PDS key, it only ever sees plaintext for the single
hop to `account-service` in between two PDS round trips. `account-service`
only ever sees plaintext and trusted `X-User-*` headers — no crypto code on
either side of it.

There are three request categories in the spec:

- **Category 1 — Session Acquiring** (`POST /pds/session`): request is
  `ECDH-ES+A256KW`/`A256GCM`-encrypted to the PDS's public key; the PDS logs
  the user into Keycloak (ROPC), mints a session + a 32-byte Session
  Encryption Key (SEK), and returns both — encrypted to the *device's*
  public key.
- **Category 2 — other BFF API** (`ALL /pds/bff/*`): request/response are
  `dir`/`A256GCM`-encrypted directly with the SEK from Category 1.
- **Category 3 — MiniApp BFF API**: same as Category 2, with the SEK sourced
  via an HTTP inquiry call instead of Postgres/Redis (`PDS_SEK_SOURCE=http`
  in this repo — a config flag, not a separate deployment).

Every payload (both categories) is also wrapped in a signed binary envelope
before encryption — see `docs/encryption-workflow.md` for the byte layout,
sequence diagrams, and full list of deviations from the spec (SQL Server
memory-optimized table → Postgres, multipart not implemented, Vault dev
mode, etc.).

Since Keycloak issues plain JWTs (no JWE, no ECDSA envelope), the
`client-simulator` CLI stands in for "the mobile app": it generates and
persists a device keypair, enrolls it with the PDS, and drives the full
Category 1 → Category 2 flow.

## Requirements

- Docker
- Docker Compose

## Start

```bash
docker compose up --build
```

This brings up Keycloak, Vault, Postgres, Redis, Kong, `auth-service` (the
PDS), and `account-service`. `client-simulator` is not started automatically
(it's a one-shot CLI — see below). Wait for everything to report healthy:

```bash
docker compose ps
```

Keycloak typically takes 20-40 seconds to become healthy on first start;
Vault and Postgres are usually faster.

## Run the demo flow

```bash
# One-time: generate a device keypair and enroll it with the PDS
docker compose run --rm client-simulator enroll

# Category 1: log in (Keycloak ROPC inside the PDS), acquire a session + SEK
docker compose run --rm client-simulator login demo-user

# Category 2: GET /accounts through the PDS (needs account.read)
docker compose run --rm client-simulator accounts

# Category 2: POST /accounts/transfer (needs account.write — demo-user will get a 403)
docker compose run --rm client-simulator transfer 250

# Same, but as admin-user (has account.write)
docker compose run --rm client-simulator login admin-user
docker compose run --rm client-simulator transfer 250
```

Device identity and the current session are persisted in a named Docker
volume (`client-simulator-data`), so repeated `docker compose run` calls
reuse the same enrolled device and don't need to re-login every time.

## Test tamper detection

```bash
docker compose run --rm client-simulator transfer-tamper 300
```

This flips a byte in the request ciphertext before sending it. Expect
`HTTP 400` with an *encrypted* error body (`{"error":"payload decryption
failed"}` or similar) — the PDS detects the corruption before the request
ever reaches `account-service`.

## Test session/SEK expiry and failure paths

- **Invalid/expired `sessionJwt`**: wait past the 4-hour session lifetime
  (or hand-edit a stored `sessionJwt`) and re-run `accounts`/`transfer` —
  expect `HTTP 401`, returned as **plaintext** JSON (no SEK is trusted yet
  at that point, so there's nothing to encrypt the error with).
- **Redis down**: `docker stop redis`, then re-run `accounts` — it should
  still succeed via the Postgres fallback (`auth-service` logs a warning,
  not an error).
- **Postgres down, cold Redis cache**: stop both `redis` and `postgres`,
  then run `accounts` for a session that was never cached — expect
  `HTTP 500` plaintext (`{"error":"session store unavailable"}`).
- **New login while Postgres is down**: `login` will fail with `HTTP 500`
  plaintext — the PDS can't durably store a new SEK.

## Inspect Kong

Kong Admin API:

```bash
curl http://localhost:8001
```

## Inspect the session store

```bash
docker exec postgres psql -U pds -d pds -c \
  "SELECT session_id, expiration_bucket, created_at FROM session_encryption_key;"
```

## Stop

```bash
docker compose down
```

## Important production changes

This POC intentionally takes shortcuts for local runnability. For production:

1. Vault runs in dev mode (unsealed, single root token, in-memory storage).
   Use a real storage backend and an AppRole policy scoped to only the
   `pds/*` paths this service touches.
2. Device enrollment (`POST /pds/device/enrollment`) has no real attestation
   — it's a bare "post your public key, get a JWT" endpoint. A production
   system needs App Attest / Play Integrity or hardware-backed key
   attestation before trusting a device's claimed public key.
3. `client-simulator`'s Category 1 login payload is a raw
   `{username, password}` — fine for a POC standing in for "the mobile app
   sends its own credentials to the PDS to relay via ROPC," but real clients
   should never hand raw passwords to any service; use an authorization-code
   + PKCE flow at the Keycloak layer instead.
4. Keycloak runs in `start-dev` mode with an in-memory H2 database and
   `sslRequired: none`. Use a real database, TLS, and a hardened realm.
5. Real-time revocation checking is not implemented — session validity is
   bounded only by the 4-hour `sessionJwt`/SEK lifetime. A production
   system may want a revocation list or shorter-lived sessions for
   sensitive operations.
6. The device keypair is reused for both ECDSA signing and as the
   `ECDH-ES+A256KW` target for the Category 1 response, rather than
   separate keys per purpose — see `docs/encryption-workflow.md`'s
   deviations section.
7. Multipart/form-data payload encryption (file uploads) is not
   implemented; `/pds/bff/*` returns `501` for that content type.
8. Postgres is a single table with a `DELETE`-based hourly cleanup, not the
   spec's SQL-Server memory-optimized, physically partitioned table.
9. Keep TLS/mTLS between Kong, `auth-service`, `account-service`, Vault,
   Postgres, and Redis — this POC runs them all in plaintext on a local
   Docker network.
10. Do not trust client-supplied identity headers — Kong's `custom-auth`
    plugin builds the `account-service` request from scratch (method, path,
    and a fresh headers table populated only from the PDS's verify
    response), so it never copies the client's original request headers
    through; nothing the client sends can end up as `X-User-*`. Still, make
    sure `account-service` is never reachable except through this plugin
    (it has no host port mapping in `docker-compose.yml`, but production
    needs network policy enforcing that too).
11. Keep business authorization in the owning microservice (already true
    here — `account-service` checks scopes itself).
12. Add circuit-breaker behavior for Keycloak/Postgres/Redis/account-service
    outages beyond the existing per-call timeouts.
13. Add audit logging without logging credentials, raw tokens, or SEKs.
14. Category 2/3 traffic costs two PDS round trips per request (verify,
    then encrypt-response) because Kong — not the PDS — makes the call to
    `account-service`. That's a deliberate trade for having Kong visibly
    gate access and own the proxy hop; a lower-latency alternative is
    having the PDS call `account-service` itself in one pass (this repo did
    exactly that in an earlier iteration — see `docs/encryption-workflow.md`
    deviations section for the trade-off).

## Main architectural decision

The PDS (`auth-service`) is the only place that ever touches key material —
Vault-held keys, the SEK-wrap KEK, per-session SEKs — end to end. Kong holds
no keys and never encrypts or decrypts on its own; for Category 1 it's a
pure pass-through, and for Category 2/3 its `custom-auth` plugin actively
checks with the PDS that auth is complete before forwarding to
`account-service` itself, then hands the reply back to the PDS to encrypt.
`account-service` sits behind Kong and stays completely free of crypto code,
on both the request and response side, trusting only the headers the plugin
sets after the PDS has verified a session.

See `docs/encryption-workflow.md` for the full request/response sequence
diagrams, the binary envelope byte layout, the key-material inventory, and
an explicit list of where this implementation simplifies the spec.
