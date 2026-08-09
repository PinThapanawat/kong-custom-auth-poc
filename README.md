# Kong + Custom Authentication Service POC

This is a runnable local POC demonstrating:

Client -> Kong -> Custom Authentication Service -> Account Service

## Architecture

```text
Client
  |
  | Authorization: Bearer demo-token
  v
Kong :8000
  |
  | POST /validate
  v
Custom Auth Service :8080
  |
  | authenticated + identity + scopes
  v
Kong
  |
  | X-User-ID
  | X-User-Scopes
  v
Account Service :8080
```

## Requirements

- Docker
- Docker Compose

## Start

```bash
docker compose up --build
```

## Test health

```bash
curl http://localhost:8000/api/accounts
```

Expected:

```json
{
  "message": "Missing Authorization header"
}
```

## Test invalid token

```bash
curl \
  -H "Authorization: Bearer wrong-token" \
  http://localhost:8000/api/accounts
```

Expected HTTP 401.

## Test valid customer token

```bash
curl \
  -H "Authorization: Bearer demo-token" \
  http://localhost:8000/api/accounts
```

Expected HTTP 200 with account information.

## Test admin token

```bash
curl \
  -H "Authorization: Bearer admin-token" \
  http://localhost:8000/api/accounts
```

Expected HTTP 200.

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

This POC intentionally uses simple demo tokens.

For production:

1. Use TLS/mTLS between Kong and Custom Auth Service.
2. Do not use static demo tokens.
3. Use a real credential/session/token validation mechanism.
4. Do not trust client-supplied identity headers.
5. Keep the Auth Service inaccessible from the Internet.
6. Add timeouts and circuit-breaker behavior.
7. Add authentication-result caching carefully.
8. Add audit logging without logging credentials.
9. Consider signed authentication context instead of plain identity headers.
10. Keep business authorization in the owning microservice.

## Main architectural decision

Kong is the API security enforcement point.

The Custom Authentication Service owns authentication.

The microservice owns resource/business authorization.
