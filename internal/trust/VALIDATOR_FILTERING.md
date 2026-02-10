# Validator Filtering

This document explains how to use validator filters in the trust package.

## Overview

The `ValidatorFilter` interface allows you to control which validators an actor (workload) is allowed to use. This enables fine-grained access control for trust validation.

## ValidatorFilter Interface

```go
type ValidatorFilter interface {
    // IsAllowed returns true if the actor is allowed to use the named validator
    IsAllowed(actor *Result, validatorName string) (bool, error)
}
```

## Available Implementations

### 1. CelValidatorFilter

Uses CEL (Common Expression Language) expressions to define policies.

**Example:**
```go
// Allow only production validators for production workloads
filter, err := trust.NewCelValidatorFilter(`
    actor.trust_domain == "prod" && validator_name in ["prod-validator-1", "prod-validator-2"]
`)

store, err := trust.NewFilteredStore(trust.WithValidatorFilter(filter))
```

**CEL Variables:**
- `actor` - The actor's Result object (subject, issuer, trust_domain, claims, etc.)
- `validator_name` - The name of the validator being evaluated

**CEL Examples:**

```cel
// Allow based on trust domain
actor.trust_domain == "production"

// Allow based on role claim
actor.claims.role == "admin"

// Allow specific validators for specific trust domains
(actor.trust_domain == "prod" && validator_name == "prod-validator") ||
(actor.trust_domain == "dev" && validator_name == "dev-validator")

// Allow any validator if actor is admin
actor.claims.role == "admin" || validator_name in ["public-validator"]

// Check issuer
actor.issuer == "https://trusted-idp.example.com"
```

### 2. AnyValidatorFilter

Composes multiple filters with OR logic - returns true if ANY filter returns true.

**Example:**
```go
// Create multiple filters
prodFilter, _ := trust.NewCelValidatorFilter(`actor.trust_domain == "prod"`)
adminFilter, _ := trust.NewCelValidatorFilter(`actor.claims.role == "admin"`)

// Combine them - allow if EITHER condition is true
anyFilter := trust.NewAnyValidatorFilter(prodFilter, adminFilter)

store, err := trust.NewFilteredStore(trust.WithValidatorFilter(anyFilter))
```

## Using FilteredStore

### Creating a Store with Validators

```go
// Option 1: Use WithCELFilter (convenience method)
store, err := trust.NewFilteredStore(
    trust.WithCELFilter(`actor.trust_domain == "prod"`),
)

// Option 2: Use WithValidatorFilter (more flexible)
filter, err := trust.NewCelValidatorFilter(`actor.claims.role == "admin"`)
store, err := trust.NewFilteredStore(
    trust.WithValidatorFilter(filter),
)

// Add named validators
store.AddValidator("prod-validator", prodValidator)
store.AddValidator("dev-validator", devValidator)
store.AddValidator("admin-validator", adminValidator)
```

### Filtering for an Actor

```go
// Get an actor's identity (e.g., from workload credential validation)
workloadResult := &trust.Result{
    Subject:     "workload-123",
    TrustDomain: "production",
    Claims: trust.Claims{
        "service": "api-gateway",
        "role":    "service",
    },
}

// Get a filtered store with only validators this actor can use
filteredStore, err := store.ForActor(ctx, workloadResult)

// Now use the filtered store to validate subject credentials
// Only validators allowed for this actor will be tried
subjectResult, err := filteredStore.Validate(ctx, subjectCredential)
```

## Complete Example

```go
package main

import (
    "context"
    "github.com/project-kessel/parsec/internal/trust"
)

func main() {
    // Create validators
    prodValidator := createProdValidator()
    devValidator := createDevValidator()
    publicValidator := createPublicValidator()
    
    // Create a filtered store with policy:
    // - Production workloads can use prod-validator
    // - Dev workloads can use dev-validator
    // - Admin role can use any validator
    // - Everyone can use public-validator
    store, err := trust.NewFilteredStore(
        trust.WithCELFilter(`
            (actor.trust_domain == "prod" && validator_name == "prod-validator") ||
            (actor.trust_domain == "dev" && validator_name == "dev-validator") ||
            (actor.claims.role == "admin") ||
            (validator_name == "public-validator")
        `),
    )
    if err != nil {
        panic(err)
    }
    
    // Add validators
    store.AddValidator("prod-validator", prodValidator)
    store.AddValidator("dev-validator", devValidator)
    store.AddValidator("public-validator", publicValidator)
    
    // Authenticate a workload
    workloadCred := getWorkloadCredential()
    workloadResult, err := someValidator.Validate(ctx, workloadCred)
    if err != nil {
        panic(err)
    }
    
    // Get validators this workload can use
    filteredStore, err := store.ForActor(ctx, workloadResult)
    if err != nil {
        panic(err)
    }
    
    // Now validate a subject credential using only allowed validators
    subjectCred := getSubjectCredential()
    subjectResult, err := filteredStore.Validate(ctx, subjectCred)
    if err != nil {
        panic(err)
    }
    
    // Use subjectResult for authorization decisions
    processRequest(workloadResult, subjectResult)
}
```

## Custom Filter Implementation

You can implement your own filters by implementing the `ValidatorFilter` interface:

```go
type MyCustomFilter struct {
    allowedValidators map[string][]string // trustDomain -> validatorNames
}

func (f *MyCustomFilter) IsAllowed(actor *trust.Result, validatorName string) (bool, error) {
    validators, ok := f.allowedValidators[actor.TrustDomain]
    if !ok {
        return false, nil
    }
    
    for _, v := range validators {
        if v == validatorName {
            return true, nil
        }
    }
    
    return false, nil
}
```

## Best Practices

1. **Principle of Least Privilege**: Grant access to only the validators a workload needs
2. **Use Trust Domains**: Organize validators by trust domain for clearer policies
3. **Admin Escape Hatch**: Consider allowing admin roles to bypass restrictions for operational flexibility
4. **Test Policies**: Write comprehensive tests for your CEL expressions
5. **Audit Logging**: Log when validators are filtered and which ones are allowed
6. **Default Deny**: If no filters are configured, FilteredStore returns all validators. Use filters to explicitly allow validators.

