# parsec Configuration

parsec uses a flexible configuration system based on [koanf](https://github.com/knadh/koanf) that supports multiple formats and sources.

## Quick Start

1. Copy an example configuration:
   ```bash
   cp configs/examples/parsec-minimal.yaml configs/parsec.yaml
   ```

2. Edit the configuration to match your environment

3. Run parsec (it will automatically load `./configs/parsec.yaml`):
   ```bash
   ./bin/parsec serve
   ```

## Configuration Sources

parsec loads configuration from multiple sources in order of precedence (highest to lowest):

1. **Command-Line Flags** - Override specific values via CLI
2. **Environment Variables** - Override any config value
3. **Configuration File** - YAML, JSON, or TOML format

### Command-Line Flags

Override specific configuration values via command-line flags (highest precedence):

```bash
# Use custom config file
./bin/parsec serve --config=/etc/parsec/config.yaml

# Override server ports
./bin/parsec serve --server-grpc-port=9091 --server-http-port=8081

# Override trust domain
./bin/parsec serve --trust-domain=prod.example.com

# Combine multiple overrides
./bin/parsec serve --config=./my-config.yaml --server-grpc-port=9091 --trust-domain=prod.example.com

# Override observability settings
./bin/parsec serve --observability-type=logging --observability-log-level=debug

# Override trust store type
./bin/parsec serve --trust-store-type=filtered_store
```

**Flag Naming Convention:**

All configuration options have corresponding command-line flags. Flag names are derived from the config file structure:
- Config path: `server.grpc_port` → Flag: `--server-grpc-port`
- Config path: `trust_domain` → Flag: `--trust-domain`
- Config path: `observability.log_level` → Flag: `--observability-log-level`

The conversion rule: replace dots (`.`) and underscores (`_`) with hyphens (`-`).

**Common flags:**
- `--config, -c` - Config file path
- `--server-grpc-port` - gRPC server port (overrides `server.grpc_port`)
- `--server-http-port` - HTTP server port (overrides `server.http_port`)
- `--trust-domain` - Trust domain for issued tokens (overrides `trust_domain`)
- `--trust-store-type` - Trust store type (overrides `trust_store.type`)
- `--observability-type` - Observability type: logging, noop, composite
- `--observability-log-level` - Log level: debug, info, warn, error

View all available flags:
```bash
./bin/parsec serve --help
```

### Configuration File

By default, parsec looks for `./configs/parsec.yaml`. You can specify a different path:

```bash
./bin/parsec serve --config=/etc/parsec/config.yaml
```

Or via environment variable:

```bash
export PARSEC_CONFIG=/etc/parsec/config.yaml
./bin/parsec serve
```

### Supported Formats

parsec auto-detects the format based on file extension:

- **YAML**: `.yaml` or `.yml` (recommended)
- **JSON**: `.json`
- **TOML**: `.toml`

See `examples/` directory for configuration examples in each format.

### Environment Variables

Environment variables override config file values. Use the `PARSEC_` prefix:

- Use **double underscore (`__`)** for nested fields
- Use **single underscore (`_`)** as part of field names

Examples:

```bash
# Override server ports
export PARSEC_SERVER__GRPC_PORT=9091
export PARSEC_SERVER__HTTP_PORT=8081

# Override trust domain
export PARSEC_TRUST_DOMAIN=prod.example.com

# Start parsec
./bin/parsec
```

Mapping rules:
- `PARSEC_SERVER__GRPC_PORT` → `server.grpc_port`
- `PARSEC_TRUST_DOMAIN` → `trust_domain`
- `PARSEC_TRUST_STORE__TYPE` → `trust_store.type`

## Configuration Reference

### Server

Network-level server configuration:

```yaml
server:
  grpc_port: 9090  # gRPC server port (ext_authz, token exchange)
  http_port: 8080  # HTTP server port (gRPC-gateway transcoding)
```

### Trust Domain

```yaml
trust_domain: "parsec.example.com"  # Audience for issued tokens
```

### Authorization Server (ext_authz)

Configure the Envoy ext_authz server behavior (optional):

```yaml
authz_server:
  token_types:
    - type: "urn:ietf:params:oauth:token-type:txn_token"
      header_name: "Transaction-Token"
    - type: "urn:ietf:params:oauth:token-type:access_token"
      header_name: "Authorization"
```

If not specified, defaults to issuing a transaction token in the `Transaction-Token` header.

### Exchange Server

Configure the token exchange server behavior:

```yaml
exchange_server:
  claims_filter:
    type: stub  # Allow all claims (passthrough)
```

The claims filter controls which request_context claims actors can provide. This is separate from the network-level `server` configuration.

### Trust Store

The trust store manages credential validators:

```yaml
trust_store:
  type: stub_store  # or "filtered_store"
  validators:
    - name: my-validator  # Required for filtered_store
      type: jwt_validator  # jwt_validator, json_validator, stub_validator
      issuer: "https://idp.example.com"
      jwks_url: "https://idp.example.com/.well-known/jwks.json"
      trust_domain: "example.com"
      refresh_interval: "15m"
```

**Validator Types:**

- `jwt_validator` - Validates JWT tokens with JWKS
- `json_validator` - Validates unsigned JSON credentials
- `stub_validator` - Testing validator (accepts any non-empty token)

**Filtered Store** (optional):

```yaml
trust_store:
  type: filtered_store
  validators:
    - name: prod-validator
      # ... validator config ...
  filter:
    type: cel
    script: |
      actor.trust_domain == "prod.example.com" && 
      validator_name == "prod-validator"
```

**Filter Types:**

- `cel` - CEL expression that evaluates to boolean
- `any` - Composite filter that allows if any sub-filter allows
- `passthrough` - Allows all validators (no filtering)

**Composite Filter Example:**

```yaml
trust_store:
  type: filtered_store
  validators:
    - name: prod-validator
    - name: dev-validator
    - name: admin-validator
  filter:
    type: any  # Allow if ANY condition matches
    filters:
      - type: cel
        script: actor.trust_domain == "prod.example.com"
      - type: cel
        script: actor.claims.admin == true
      - type: cel
        script: validator_name == "dev-validator"
```

### Data Sources

Data sources enrich tokens with external data:

```yaml
data_sources:
  - name: identity-policy
    type: static
    data:
      internal_idp_target: "https://sso.redhat.com/auth/realms/internal"
      role_fallback_enabled: true
  - name: user_roles
    type: lua
    script_file: ./scripts/user_roles.lua  # Or use inline script
    config:  # Available to Lua script via config.get()
      api_url: "https://api.example.com"
      api_key: "secret-key"  # Inject via env: PARSEC_DATA_SOURCES__0__CONFIG__API_KEY
    http:  # HTTP client configuration
      timeout: 30s
      # Optional: Use fixtures for testing (no real HTTP calls)
      # fixtures_file: ./test/fixtures/user_api.yaml
      # fixtures_dir: ./test/fixtures/
    caching:
      type: in_memory  # or "distributed", "none"
      ttl: 5m
```

**HTTP Configuration:**

- `timeout` - Duration string for HTTP request timeout (default: 30s)
- `fixtures_file` - Path to YAML/JSON fixtures file (for testing)
- `fixtures_dir` - Path to directory containing fixtures (for testing)

**Caching Types:**

- `in_memory` - Local cache (single instance)
- `distributed` - Groupcache-based distributed cache
- `none` - No caching

### Claim Mappers

Claim mappers build token claims from inputs:

```yaml
claim_mappers:
  transaction_context:  # Builds "tctx" claim
    - type: passthrough  # Pass through subject claims
    - type: cel
      script: |
        {
          "roles": datasource("user_roles").roles,
          "org": datasource("org_metadata").org_id
        }
  
  request_context:  # Builds "req_ctx" claim
    - type: request_attributes  # Include request path, method, etc.
```

**Mapper Types:**

- `passthrough` - Pass through subject claims
- `request_attributes` - Include request metadata (path, method, IP, etc.)
- `cel` - CEL expression returning a map of claims
- `stub` - Fixed claims (for testing)

### Issuers

Issuers create tokens:

```yaml
issuers:
  - token_type: "urn:ietf:params:oauth:token-type:txn_token"
    type: stub  # stub, unsigned, transaction_token
    issuer_url: "https://parsec.example.com"
    ttl: 5m
```

**Token Types:**

- `urn:ietf:params:oauth:token-type:txn_token` - Transaction token (RFC draft)
- `urn:ietf:params:oauth:token-type:access_token` - OAuth2 access token
- `urn:ietf:params:oauth:token-type:jwt` - Generic JWT token

**Issuer Types:**

- `stub` - Simple test tokens (includes subject and transaction ID)
- `unsigned` - Base64-encoded JSON tokens (never expires); use with CEL (for example `configs/scripts/redhat_identity.cel`) to emit the x-rh-identity envelope for `urn:redhat:params:oauth:token-type:rh-identity`
- `transaction_token` - Signed transaction tokens using a KeyManager (follows OAuth transaction token spec)

## Examples

The `examples/` directory contains complete configuration examples:

- **`parsec-minimal.yaml`** - Simplest working config (stubs only)
- **`parsec-full.yaml`** - Comprehensive example with all features
- **`parsec-production.yaml`** - Production-ready configuration
- **`parsec-minimal.json`** - Minimal config in JSON format
- **`parsec-minimal.toml`** - Minimal config in TOML format

## OpenShift Deployment - Clowder Envs

When deploying parsec to OpenShift, the platform requires specific ports that differ from the upstream defaults:

| Port | Upstream default | OpenShift |
|------|-----------------|-----------|
| gRPC | 9090 | 9800 |
| HTTP | 8080 | 8000 |
| Metrics | (served on HTTP port at `/metrics`) | 9000 (platform convention) |

**The upstream code and config files intentionally retain the original defaults (9090/8080).** Port overrides for OpenShift are applied at the deployment layer, not in application code.

### How ports are overridden

The deployment templates in `deploy/` handle this:

- **Ephemeral environments** (`deploy/parsec-ephem.yaml`): The ConfigMap is defined inline within the template with `grpc_port: 9800` and `http_port: 8000`. Health probes and `h2cTargetPort` match these ports.

- **Stage/Production environments** (`deploy/parsec.yaml`): The config is provided via an external Secret (or ConfigMap created downstream) that specifies the OpenShift ports. The deployment template's probes and `h2cTargetPort` are already set to the OpenShift ports.

This works because koanf loads config with this precedence: **file > defaults**. The mounted config file's port values override the built-in defaults at startup.

### Creating a downstream ConfigMap for non-ephemeral environments

```bash
# Create a Secret with the production config (ports set to OpenShift values)
oc create secret generic parsec-config \
  --from-file=parsec.yaml=path/to/production-parsec.yaml \
  --from-file=scripts/redhat_identity.cel=configs/scripts/redhat_identity.cel
```

The production `parsec.yaml` should include:
```yaml
server:
  grpc_port: 9800
  http_port: 8000
```

### Local development

For local development, no port overrides are needed. The upstream defaults (9090/8080) work out of the box:
```bash
./bin/parsec serve
# gRPC on :9090, HTTP on :8080
```

## Hot Reloading

Configuration hot reloading is supported but not yet enabled by default. The infrastructure is in place in `internal/config/loader.go` with the `Watch()` method.

## Configuration Validation

parsec validates configuration at startup and will fail with descriptive errors if:

- Required fields are missing
- Invalid types are specified
- Files referenced (e.g., Lua scripts) don't exist
- URLs or durations are malformed

## Security Considerations

### Sensitive Data

Avoid hardcoding sensitive data in configuration files:

```yaml
# BAD - hardcoded secret
config:
  api_key: "secret123"

# GOOD - reference environment variable
config:
  api_key: "${API_KEY}"
```

### File Permissions

Restrict access to configuration files:

```bash
chmod 600 /etc/parsec/config.yaml
chown parsec:parsec /etc/parsec/config.yaml
```

### Environment Variables

For production deployments, prefer:
- Kubernetes Secrets mounted as environment variables
- HashiCorp Vault
- AWS Secrets Manager / GCP Secret Manager

## Configuration Precedence Examples

Understanding how configuration sources work together:

### Example 1: All defaults
```bash
# Uses ./configs/parsec.yaml with no overrides
./bin/parsec serve
```
Result: All values from config file

### Example 2: Environment variable override
```bash
# Config has grpc_port: 9090
# Env var overrides it to 9091
PARSEC_SERVER__GRPC_PORT=9091 ./bin/parsec serve
```
Result: gRPC on port 9091, everything else from config

### Example 3: Flag override (highest precedence)
```bash
# Config has grpc_port: 9090
# Env var sets it to 9091
# Flag overrides both to 9092
PARSEC_SERVER__GRPC_PORT=9091 ./bin/parsec serve --server-grpc-port=9092
```
Result: gRPC on port 9092 (flag wins)

### Example 4: Combining sources
```yaml
# configs/prod.yaml
server:
  grpc_port: 9090
  http_port: 8080
trust_domain: "prod.example.com"
```

```bash
# Override specific values while keeping the rest
PARSEC_TRUST_DOMAIN=prod-us.example.com \
  ./bin/parsec serve \
  --config=./configs/prod.yaml \
  --server-http-port=8081
```

Result:
- grpc_port: 9090 (from config)
- http_port: 8081 (from flag)
- trust_domain: prod-us.example.com (from env var)

## Troubleshooting

### Config file not found

```
Error: failed to load config: failed to load config file ./configs/parsec.yaml: ...
```

**Solution**: Create the config file or use `--config` flag to point to an existing file.

### Invalid format

```
Error: failed to parse config: ...
```

**Solution**: Validate your YAML/JSON/TOML syntax. Use a linter or validator.

### Environment variables not working

**Issue**: Env vars not overriding config values

**Solution**: Use double underscore (`__`) for nesting:
- `PARSEC_SERVER__GRPC_PORT` (correct)
- `PARSEC_SERVER_GRPC_PORT` (wrong - will look for field named `server_grpc_port`)

### Flags not working

**Issue**: Flag values not being applied

**Solution**: Ensure you're using the `serve` command and correct flag names:
- `./bin/parsec serve --server-grpc-port=9091` (correct)
- `./bin/parsec --server-grpc-port=9091` (wrong - flags are command-specific)
- `./bin/parsec serve --grpc-port=9091` (wrong - old flag name, use --server-grpc-port)

## Further Reading

- [Architecture Documentation](../ARCHITECTURE.md)
- [Lua Data Sources](../internal/datasource/LUA_DATASOURCE.md)
- [CEL Mappers](../internal/cel/README.md)
- [Validator Filtering](../internal/trust/VALIDATOR_FILTERING.md)

