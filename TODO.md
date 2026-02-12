# parsec TODO

This document tracks planned work and next steps for the parsec project.

## End to end

- [X] Example set up that issues tokens compatible with identity header

## Experiments
Functionality not yet well understood or yet lacking confidence the current architecture is correct.

### Testability / test fixtures / "hermetic" mode

- [X] Ability to define http fixtures for lua data sources which return fixture responses instead of actually making an http call
- [~] Example using production config with fixtures overlaid to write tests against input/output pairs
- [X] Ability to stand up hermetic server with fixture APIs (credential issuers)
- [X] Support key managemetn fixtures

### HTTP configuration for data sources

- [ ] Ability to define different authentication methods and have them utilized automatically rather than making the data source implementations do this
- [ ] Other HTTP configuration like retries, timeouts

### Data source reliability

- [ ] Is it possible to fall back to older data, if cached, in case a data source does not respond?
- [ ] Can we make data source fetching async so the cache is used while it is refreshed?
- [ ] Option to set up groupcache server

### Context reuse / chaining
Sometimes there is existing transaction context which should be used. It can either be context for a new token, or maybe the token can be reused as-is (same transaction trust domain).

### Meta authorization
Different callers (actors) have different privileges in terms of...

- [X] subject token types allowed (e.g. what trust domain, if unsigned is allowed). Implemented: see `FilteredStore`
- [X] subject token claims allowed to use unsigned tokens for. Implemented: see `JSONValidator`
- [ ] what context types are allowed (again, what trust domain, if unsigned is allowed). First requires context reuse from above.
- [ ] what token types they can request

## Features
Functionality with well understood expectations and relatively high confidence that it is doable within the current architecture.

### Real JWT Issuer
Implement actual JWT signing with private keys:
- [X] Integrate with key management (Spire KeyManager or alternatives)
- [X] Proper transaction token claims structure
- [X] Public key exposure via JWKS endpoint
- [ ] Ensure state store works with multiple signing issuers
- [X] 2nd pass on concurrency control
- [ ] Implement persistent key store with ConfigMap
- [ ] Validate AWS KMS works and performs well

### Static Trust Store
Load trust domain configuration from YAML:
- [X] Define configuration schema
- [X] Multi-issuer support
- [X] JWKS URL configuration per issuer

### Configuration Management
Complete configuration loading:
- [X] YAML configuration file format
- [X] Environment variable overrides
- [ ] Validation and hot reload (optional, helps avoid unnecessarily clearing cache)

### Observability
Add structured logging and metrics. Would like to experiment with observability achitecture patterns. (e.g. https://martinfowler.com/articles/domain-oriented-observability.html)

- [ ] Request/response logging
- [ ] Token issuance metrics
- [ ] Data source performance metrics
- [ ] Distributed tracing

### Production Hardening
- [ ] Graceful shutdown
- [X] Health checks – use standard grpc health protocol (separate readiness and liveness services)
- [ ] Circuit breakers for external calls / caching failures (failing open vs closed)

