package mapper

import (
	"context"
	"fmt"

	"github.com/google/cel-go/cel"

	celhelpers "github.com/project-kessel/parsec/internal/cel"
	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// CELMapper is a ClaimMapper that uses CEL (Common Expression Language) expressions
// to produce claims from the MapperInput.
//
// The CEL expression has access to the following variables:
//   - datasource(name) - function to fetch data from a named data source
//   - subject - the subject identity information as a map
//   - actor - the actor identity information as a map
//   - request - the request attributes as a map
//
// The expression should evaluate to a map that will be used as the claims.
//
// Example CEL expressions:
//
//	// Simple claim from subject
//	{"user": subject.subject}
//
//	// Fetch from data source
//	{"roles": datasource("user_roles").roles}
//
//	// Conditional logic
//	subject.trust_domain == "prod" ? {"env": "production"} : {"env": "dev"}
//
//	// Complex expressions
//	{
//	  "user": subject.subject,
//	  "ip": request.ip_address,
//	  "roles": datasource("user_roles").roles,
//	  "region": datasource("geo").region
//	}
type CELMapper struct {
	script string
	ast    *cel.Ast // Pre-compiled AST
}

// NewCELMapper creates a new CEL-based claim mapper
// The script should be a CEL expression that evaluates to a map of claims
func NewCELMapper(script string) (*CELMapper, error) {
	if script == "" {
		return nil, fmt.Errorf("CEL script cannot be empty")
	}

	// Compile the script once at construction time
	// Use a test environment with nil datasources for compilation
	env, err := cel.NewEnv(
		celhelpers.MapperInputLibrary(context.Background(), nil, nil),
		celhelpers.RedHatHelpersLibrary(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	ast, issues := env.Compile(script)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("failed to compile CEL script: %w", issues.Err())
	}

	return &CELMapper{
		script: script,
		ast:    ast,
	}, nil
}

// Map evaluates the CEL expression and returns the resulting claims
func (m *CELMapper) Map(ctx context.Context, input *service.MapperInput) (claims.Claims, error) {
	if input == nil {
		return nil, fmt.Errorf("mapper input cannot be nil")
	}

	// Create CEL environment with the datasource registry for this invocation
	// This provides the runtime context (datasources) without recompiling
	// TODO: this could be at least constructed per token service invocation, rather than per source
	// TODO: we could also make this constructed once per application, and use macros to bind convenience functions to input
	env, err := cel.NewEnv(
		celhelpers.MapperInputLibrary(ctx, input.DataSourceRegistry, input.DataSourceInput),
		celhelpers.RedHatHelpersLibrary(),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	// Create program from the pre-compiled AST with the runtime environment
	// This allows us to inject different datasources per invocation
	program, err := env.Program(m.ast)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL program: %w", err)
	}

	// Create activation with variables for this invocation
	activation := m.createActivation(ctx, input)

	// Evaluate the program with the activation
	result, _, err := program.Eval(activation)
	if err != nil {
		return nil, fmt.Errorf("failed to evaluate CEL expression: %w", err)
	}

	// Convert CEL result to native Go value
	resultValue := celhelpers.ConvertCELValue(result)
	if resultValue == nil {
		return nil, nil
	}

	// Result should be a map
	resultMap, ok := resultValue.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("CEL expression must evaluate to a map, got: %T", resultValue)
	}

	return claims.Claims(resultMap), nil
}

// Script returns the CEL script used by this mapper
func (m *CELMapper) Script() string {
	return m.script
}

// createActivation creates a CEL activation with variables
func (m *CELMapper) createActivation(ctx context.Context, input *service.MapperInput) map[string]any {
	activation := map[string]any{
		// subject, actor, and request are provided as direct values
		// Access them in CEL as: subject.field, actor.field, request.field
		"subject": func() any {
			if input.Subject == nil {
				return nil
			}
			return trustResultToMap(input.Subject)
		}(),

		"actor": func() any {
			if input.Actor == nil {
				return nil
			}
			return trustResultToMap(input.Actor)
		}(),

		"request": func() any {
			if input.RequestAttributes == nil {
				return nil
			}

			return map[string]any{
				"method":     input.RequestAttributes.Method,
				"path":       input.RequestAttributes.Path,
				"ip_address": input.RequestAttributes.IPAddress,
				"user_agent": input.RequestAttributes.UserAgent,
				"headers":    input.RequestAttributes.Headers,
				"additional": input.RequestAttributes.Additional,
			}
		}(),
	}

	return activation
}

// trustResultToMap converts a trust.Result to a map for CEL access
func trustResultToMap(result *trust.Result) map[string]any {
	m := map[string]any{
		"subject":      result.Subject,
		"issuer":       result.Issuer,
		"trust_domain": result.TrustDomain,
		"expires_at":   result.ExpiresAt,
		"issued_at":    result.IssuedAt,
	}

	if len(result.Claims) > 0 {
		m["claims"] = map[string]any(result.Claims)
	}

	if len(result.Audience) > 0 {
		m["audience"] = result.Audience
	}

	if result.Scope != "" {
		m["scope"] = result.Scope
	}

	return m
}
