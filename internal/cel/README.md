# CEL Package

This package provides CEL (Common Expression Language) support for the Parsec token exchange service.

## Overview

CEL is a non-Turing complete expression language designed to be fast, portable, and safe to execute. It's ideal for performance-critical applications where user-provided expressions need to be evaluated safely.

## Custom Functions and Variables

This package provides CEL extensions specifically for claim mapping in Parsec:

### Variables

- **`subject`** - Subject identity information (map)
  - `subject.subject` - Subject identifier
  - `subject.issuer` - Issuer URL
  - `subject.trust_domain` - Trust domain
  - `subject.claims` - Additional claims from the credential
  - `subject.audience` - Intended audience
  - `subject.scope` - OAuth2 scope

- **`config`** - Configuration values from parsec.yaml identity section (map)

- **`workload`** - Workload identity information (map, same structure as subject)

- **`request`** - Request attributes (map)
  - `request.method` - HTTP method
  - `request.path` - Request path
  - `request.ip_address` - Client IP address
  - `request.user_agent` - User agent string
  - `request.headers` - HTTP headers
  - `request.additional` - Additional context

### Functions

- **`datasource(name)`** - Fetches data from a named data source
  - Takes a string argument (datasource name)
  - Returns the fetched data (typically a map or list)
  - Returns null if the datasource doesn't exist
  - Results are automatically cached within a single evaluation

- **`fail(message)`** - Rejects the input
  - Aborts evaluation and returns a `ClaimMappingError`
  - Use when the mapper cannot process the input (e.g. unrecognised token type)

## Example CEL Expressions

### Simple Claims from Subject

```cel
{
  "user": subject.subject,
  "domain": subject.trust_domain
}
```

### Conditional Logic

```cel
subject.trust_domain == "prod" 
  ? {"env": "production", "level": "high"} 
  : {"env": "dev", "level": "low"}
```

### Rejecting Input

```cel
isSupportedToken(subject.claims)
  ? { "identity": { ... }, "entitlements": {} }
  : fail("unsupported_token_type")
```

### Fetching from Data Sources

```cel
{
  "user": subject.subject,
  "roles": datasource("user_roles").roles,
  "region": datasource("geo_lookup").region
}
```

### Complex Expressions

```cel
{
  "identity": subject.subject + "@" + subject.trust_domain,
  "source_ip": request.ip_address,
  "permissions": datasource("permissions").for_user(subject.subject),
  "is_admin": "admin" in datasource("user_roles").roles
}
```

## Performance Considerations

The CEL mapper compiles and evaluates expressions for each token issuance. While CEL evaluation is very fast (nanoseconds to microseconds), for high-throughput scenarios, consider:

1. Keeping expressions simple and focused
2. Minimizing datasource calls
3. Using caching datasources when appropriate

Datasource results are automatically cached within a single evaluation, so calling the same datasource multiple times in one expression only fetches once.

## References

- [CEL Language Specification](https://github.com/google/cel-spec)
- [CEL-Go Documentation](https://pkg.go.dev/github.com/google/cel-go/cel)
- [CEL-Go Codelab](https://codelabs.developers.google.com/codelabs/cel-go)

