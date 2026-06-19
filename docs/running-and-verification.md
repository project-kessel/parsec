# Running Parsec Locally & Endpoint Verification

This document describes how to build, run, and verify all parsec endpoints locally using the minimal stub configuration.

## Prerequisites

- Go 1.22+ (with `GOEXPERIMENT=jsonv2` support)
- `grpcurl` (for gRPC endpoint testing)
- `curl` (for HTTP endpoint testing)

## Build

```bash
GOEXPERIMENT=jsonv2 go build -ldflags "-X cmd.Version=dev" -o ./bin/parsec ./cmd/parsec
```

Or use the Makefile (does not require FIPS):

```bash
make local-build
```

## Run

Start parsec with the minimal configuration:

```bash
GOEXPERIMENT=jsonv2 ./bin/parsec serve --config configs/examples/parsec-minimal.yaml
```

Expected startup log:

```json
{
  "level": "info",
  "grpc_addr": "0.0.0.0:9090",
  "http_addr": "0.0.0.0:8080",
  "token_exchange_url": "http://0.0.0.0:8080/v1/token",
  "jwks_url": "http://0.0.0.0:8080/v1/jwks.json",
  "jwks_wellknown_url": "http://0.0.0.0:8080/.well-known/jwks.json",
  "trust_domain": "parsec.example.com",
  "message": "parsec is running"
}
```

## Ports

| Protocol | Port | Description |
|----------|------|-------------|
| gRPC | 9090 | ext_authz, TokenExchange, JWKS, Health, Reflection |
| HTTP | 8080 | grpc-gateway transcoding, health probes |

## Endpoint Verification

### 1. Liveness Probe

```bash
curl -s http://localhost:8080/healthz/live
```

**Expected response (200 OK):**
```json
{"status":"OK"}
```

### 2. Readiness Probe

```bash
curl -s http://localhost:8080/healthz/ready
```

**Expected response (200 OK):**
```json
{"status":"SERVING"}
```

### 3. JWKS Endpoint

```bash
curl -s http://localhost:8080/v1/jwks.json
```

**Expected response (200 OK):**
```json
{"keys":[]}
```

> Empty key set is expected with stub issuer. Production configurations with `transaction_token` issuers and signing keys will return actual JWK entries.

The well-known alias also works:

```bash
curl -s http://localhost:8080/.well-known/jwks.json
```

### 4. Token Exchange (HTTP - form-urlencoded)

```bash
curl -s -X POST http://localhost:8080/v1/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=my-test-bearer-token" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  -d "audience=parsec.example.com"
```

**Expected response (200 OK):**
```json
{
  "access_token": "stub-txn-token.test-subject.txn-<nonce>.{\"requested_audience\":\"parsec.example.com\"}",
  "issued_token_type": "urn:ietf:params:oauth:token-type:txn_token",
  "token_type": "Bearer",
  "expires_in": "300"
}
```

### 5. Token Exchange (HTTP - JSON)

```bash
curl -s -X POST http://localhost:8080/v1/token \
  -H "Content-Type: application/json" \
  -d '{
    "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
    "subject_token": "my-test-bearer-token",
    "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
    "audience": "parsec.example.com"
  }'
```

**Expected response (200 OK):**
```json
{
  "accessToken": "stub-txn-token.test-subject.txn-<nonce>.{\"requested_audience\":\"parsec.example.com\"}",
  "issuedTokenType": "urn:ietf:params:oauth:token-type:txn_token",
  "tokenType": "Bearer",
  "expiresIn": "300",
  "scope": "",
  "refreshToken": ""
}
```

> Note: JSON responses use camelCase field names per protobuf JSON mapping.

### 6. Token Exchange (gRPC)

```bash
grpcurl -plaintext -d '{
  "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
  "subject_token": "test-grpc-bearer-token",
  "subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
  "audience": "parsec.example.com"
}' localhost:9090 parsec.v1.TokenExchangeService/Exchange
```

**Expected response:**
```json
{
  "accessToken": "stub-txn-token.test-subject.txn-<nonce>.{\"requested_audience\":\"parsec.example.com\"}",
  "issuedTokenType": "urn:ietf:params:oauth:token-type:txn_token",
  "tokenType": "Bearer",
  "expiresIn": "300"
}
```

### 7. ext_authz Check (gRPC - with credentials)

```bash
grpcurl -plaintext -d '{
  "attributes": {
    "request": {
      "http": {
        "method": "GET",
        "path": "/api/v1/resources",
        "headers": {
          "authorization": "Bearer my-test-token",
          "user-agent": "curl/8.0",
          "host": "api.example.com"
        }
      }
    },
    "source": {
      "address": {
        "socket_address": {
          "address": "192.168.1.100",
          "port_value": 12345
        }
      }
    }
  }
}' localhost:9090 envoy.service.auth.v3.Authorization/Check
```

**Expected response (OK - allowed):**
```json
{
  "status": {},
  "okResponse": {
    "headers": [
      {
        "header": {
          "key": "Transaction-Token",
          "value": "stub-txn-token.test-subject.txn-<nonce>.{\"host\":\"\",\"ip_address\":\"192.168.1.100\",\"method\":\"GET\",\"path\":\"/api/v1/resources\",\"user_agent\":\"curl/8.0\"}"
        }
      }
    ],
    "headersToRemove": ["authorization"]
  }
}
```

Key observations:
- `status: {}` means gRPC code 0 (OK) — request is allowed
- `Transaction-Token` header is injected for downstream services
- `authorization` header is stripped (security boundary)
- Request attributes (method, path, IP, user-agent) are embedded in the token

### 8. ext_authz Check (gRPC - no credentials, denied)

```bash
grpcurl -plaintext -d '{
  "attributes": {
    "request": {
      "http": {
        "method": "GET",
        "path": "/api/v1/resources",
        "headers": {
          "user-agent": "curl/8.0",
          "host": "api.example.com"
        }
      }
    }
  }
}' localhost:9090 envoy.service.auth.v3.Authorization/Check
```

**Expected response (denied):**
```json
{
  "status": {
    "code": 16,
    "message": "failed to extract credentials: no credential"
  },
  "deniedResponse": {
    "body": "failed to extract credentials: no credential"
  }
}
```

### 9. gRPC Health Check

```bash
grpcurl -plaintext -d '{"service": ""}' localhost:9090 grpc.health.v1.Health/Check
```

**Expected response:**
```json
{
  "status": "SERVING"
}
```

### 10. gRPC Service Discovery

```bash
grpcurl -plaintext localhost:9090 list
```

**Expected output:**
```
envoy.service.auth.v3.Authorization
grpc.health.v1.Health
grpc.reflection.v1.ServerReflection
grpc.reflection.v1alpha.ServerReflection
parsec.v1.JWKSService
parsec.v1.TokenExchangeService
```

## Error Cases

### Wrong audience

```bash
curl -s -X POST http://localhost:8080/v1/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "subject_token=test-token" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt" \
  -d "audience=wrong.audience.com"
```

**Response:**
```json
{"code":2, "message":"requested audience \"wrong.audience.com\" does not match trust domain \"parsec.example.com\""}
```

### Unsupported grant type

```bash
curl -s -X POST http://localhost:8080/v1/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=client_credentials" \
  -d "subject_token=test-token" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:jwt"
```

**Response:**
```json
{"code":2, "message":"unsupported grant_type: client_credentials"}
```

## Verification Summary

| # | Endpoint | Method | Result |
|---|----------|--------|--------|
| 1 | `/healthz/live` | GET | 200 OK |
| 2 | `/healthz/ready` | GET | 200 SERVING |
| 3 | `/v1/jwks.json` | GET | 200 (empty keys with stub) |
| 4 | `/.well-known/jwks.json` | GET | 200 (empty keys with stub) |
| 5 | `/v1/token` (form) | POST | 200 — token issued |
| 6 | `/v1/token` (JSON) | POST | 200 — token issued |
| 7 | `TokenExchangeService/Exchange` | gRPC | OK — token issued |
| 8 | `Authorization/Check` (auth) | gRPC | OK — Transaction-Token injected |
| 9 | `Authorization/Check` (no auth) | gRPC | Denied — code 16 Unauthenticated |
| 10 | `Health/Check` | gRPC | SERVING |
| 11 | `/v1/token` (bad audience) | POST | Error — audience mismatch |
| 12 | `/v1/token` (bad grant) | POST | Error — unsupported grant_type |

All endpoints behave as expected with the minimal stub configuration.

## Running Tests

```bash
GOEXPERIMENT=jsonv2 go test ./... -count=1 -race -short
```

All 22 packages pass with zero failures.
