# Payload Decryptor Service (PDS): request/response encryption

## Category 1 — Session Acquiring

```mermaid
sequenceDiagram
    participant Device as Mobile Device
    participant Kong
    participant PDS as PDS
    participant Auth as auth-service
    participant Keycloak

    Note over Device,PDS: One-time: device enrollment
    Device->>Kong: POST /pds/device/enrollment {devicePublicKeyJwk}
    Kong->>PDS: (routed, no crypto)
    PDS-->>Device: {deviceId, deviceJwt}<br/>deviceJwt = ES256 JWT, signed by PDS,<br/>claims = {deviceId, devicePublicKeyJwk}

    Note over Device,Keycloak: Login (Category 1) — PIN or biometric authentication
    Device->>Device: build signed envelope {pin, bioAuthToken}<br/>sign with device private key (ECDSA P-256)
    Device->>Device: JWE-encrypt envelope to PDS's public key<br/>(ECDH-ES+A256KW / A256GCM)
    Device->>Kong: POST /pds/session<br/>Authorization: Bearer deviceJwt
    Kong->>PDS: (routed)
    PDS->>PDS: verify deviceJwt, decrypt JWE,<br/>verify envelope signature
    PDS->>Auth: POST /internal/login {pin, bioAuthToken}
    Auth->>Keycloak: login (grant_type=password,<br/>pin/bioAuthToken used as the credential)
    Keycloak-->>Auth: access_token
    Auth-->>PDS: {sub, roles, scopes}
    PDS->>PDS: generate sessionId + 32-byte SEK<br/>store SEK + AES-256-GCM-encrypted <br/>(Database primary, Redis 4h cache)<br/>issue sessionJwt by Keycloak Keypair (ES256, 4h)
    PDS-->>Device: build response encrypted by device public key
    Device->>Device: decrypt with device private key<br/>verify signature with PDS's public key<br/>extract sessionJwt + SEK
```

## Category 2 — other ONEApp BFF API

```mermaid
sequenceDiagram
    participant Device as Mobile Device
    participant Kong as Kong (custom-auth plugin)
    participant Crypto as Cryptography-Service
    participant PDS as PDS
    participant Account as account-service

    Device->>Device: build request body <br/> sign using device private key <br/> encrypt using SEK 
    Device->>Kong: request /pds/bff/...<br/>Authorization: Bearer sessionJwt

    Kong->>Crypto: POST /pds/internal/verify<br/>{sessionJwt, jwe, method, upstreamPath, requestUniqueId}
    Crypto->>Crypto: Validate sessionJwt signature , expiry date/time (401 plaintext on failure)
    Crypto->>PDS:GET SEK and device public key<br/>(sessionId)
    PDS-->>Crypto: Return SEK and Device Public Key (or not found)<br/>Redis

    alt SEK not found / db error
        Crypto-->>Kong: 401 not-found / 500 db-error<br/>(plaintext)
        Kong-->>Device: 401 not-found / 500 db-error<br/>(plaintext)
    else SEK found
        Crypto->>Crypto: decrypt payload with SEK and check signing by device public key (400 decrypt on failure)

        Crypto-->>Kong: outcome: authenticated | unauthenticated | rejected<br/>(+ plaintext body, sessionId, X-User-* fields, when authenticated)

        alt not authenticated
            Kong-->>Device: relay Cryptography-Service's ready-made response verbatim<br/>(plaintext JSON 401, or pre-encrypted JWE 400)
        else authenticated
            Kong->>Account: plaintext request + trusted X-User-* headers<br/>(Kong calls account-service directly via resty.http)
            Account-->>Kong: plaintext response<br/>(Kong itself synthesizes 504/502 on timeout/connection failure)
            Kong->>Crypto: POST /pds/internal/encrypt-response<br/>{sessionId, requestUniqueId, plaintextBodyBase64}
            Crypto->>Crypto: build 0x00 response envelope, signing with pdsSignKeyPair from Vault,<br/>JWE-encrypt with SEK
            Crypto-->>Kong: {responseJwe}
            Kong-->>Device: responseJwe, copying account-service's status<br/>(or Kong's own synthesized 502/504)
        end
    end

    Device->>Device: decrypt with SEK, verify signature
```



## Check with Challenge Token
```mermaid
sequenceDiagram
    participant Device as Mobile Device
    participant Kong as Kong (custom-auth plugin)
    participant Crypto as Cryptography-Service
    participant PDS as PDS
    participant Keycloak
    participant Account as account-service

    Device->>Kong: request /pds/bff/...<br/>X-Require-Revocation-Check: true
    Kong->>Crypto: POST /pds/internal/verify<br/>{..., requireRevocationCheck: true}
    Crypto->>Crypto: Validate sessionJwt signature, expiry date/time  (401 plaintext on failure)
    Crypto->>PDS: GET SEK and Device public key<br/>(sessionId)
    PDS-->>Crypto: Return SEK and Device Public Key (or not found)<br/>Redis

    alt SEK not found / db error
        Crypto-->>Kong: 401 not-found / 500 db-error<br/>(plaintext)
        Kong-->>Device: 401 not-found / 500 db-error<br/>(plaintext)
    else SEK found
        Crypto->>Keycloak: what is key to introspect ????? introspect to Keycloak<br/>POST /realms/poc/protocol/openid-connect/token/introspect
        Keycloak-->>Crypto: {active: true|false}
        alt inactive (revoked/logged out)
            Crypto-->>Kong: outcome: rejected, 401, encrypted {"error":"session revoked"}
            Kong-->>Device: relay Cryptography-Service's encrypted 401 verbatim
        else active
            Crypto->>Crypto: decrypt payload with SEK and check singing by Device Public Key(400 decrypt on failure)

            Crypto->>Crypto: decrypt challengeJWE with CommonServicEncrypted(Vault)<br/>check issue of challengeJWT by CommonServiceSign(Vault)<br/>(400 decrypt on failure)
            Crypto-->>Kong: outcome: authenticated<br/>(+ plaintext body, sessionId, X-User-* fields)
            Kong->>Account: plaintext request + trusted X-User-* headers
            Account-->>Kong: plaintext response
            Kong->>Crypto: POST /pds/internal/encrypt-response<br/>{sessionId, requestUniqueId, plaintextBodyBase64}
            Crypto->>Crypto: build 0x00 response envelope, signing with pdsSignKeyPair from Vault,<br/>JWE-encrypt with SEK
            Crypto-->>Kong: {responseJwe}
            Kong-->>Device: responseJwe, copying account-service's status
        end
    end
```




## Key material

| Key | Generated | Held by | Purpose |
|---|---|---|---|
| `pdsEncKeyPair` (EC P-256) | PDS startup, once (persisted in Vault) | Vault (`secret/data/pds/ec-enc-keypair`) | `ECDH-ES+A256KW` target for Category 1 request decryption / response encryption |
| `pdsSignKeyPair` (EC P-256) | PDS startup, once (persisted in Vault) | Vault (`secret/data/pds/ec-sign-keypair`) | ES256-signs `deviceJwt`, `sessionJwt`, and every response envelope |
| Device keypair (EC P-256) | Client, once, persisted locally | Client only (private half never leaves the device) | Signs every request envelope; also the `ECDH-ES+A256KW` target for the Category 1 response (see deviation below) |
| SEK (AES-256) | PDS, per session | Database (AESWrap-wrapped) + Redis (4h cache); device via the Category 1 response | `dir`+`A256GCM` content key for all Category 2/3 request/response bodies |
| SEK-wrap KEK (AES-256) | PDS startup, once (persisted in Vault) | Vault (`secret/data/pds/sek-wrap-kek`) | RFC 3394 AESWrap key-encryption-key protecting SEKs at rest in Database; also encrypts the refresh token below (`tokenCrypto.ts`) |

