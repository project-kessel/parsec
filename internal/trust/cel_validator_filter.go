package trust

import (
	"encoding/json"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"

	"github.com/project-kessel/parsec/internal/request"
)

// ValidatorFilterLibrary creates a CEL library for filtering validators based on actor context.
//
// This provides compile-time declarations for:
//   - actor - the actor's Result object as a map (subject, issuer, trust_domain, claims, etc.)
//   - validator_name - the name of the validator being checked (string)
//   - request - the request attributes as a map (method, path, headers, additional, etc.)
//
// The CEL expression should evaluate to a boolean indicating whether the validator is allowed.
//
// Example expressions:
//   - actor.trust_domain == "prod" && validator_name == "prod-validator"
//   - actor.claims.role == "admin"
//   - validator_name in ["validator1", "validator2"] && actor.trust_domain == "trusted"
//   - request.path.startsWith("/api/admin") && actor.claims.role == "admin"
//   - request.additional.context_extensions.env == "prod"
func ValidatorFilterLibrary() cel.EnvOption {
	return cel.Lib(&validatorFilterLib{})
}

type validatorFilterLib struct{}

func (lib *validatorFilterLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		// Declare actor as a dynamic type (will be a map)
		cel.Variable("actor", cel.DynType),
		// Declare validator_name as a string
		cel.Variable("validator_name", cel.StringType),
		// Declare request as a dynamic type (will be a map)
		cel.Variable("request", cel.DynType),
	}
}

func (lib *validatorFilterLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

// ConvertResultToMap converts a Result to a map[string]any for CEL evaluation
func ConvertResultToMap(result *Result) (map[string]any, error) {
	if result == nil {
		return nil, nil
	}

	// Use JSON marshaling/unmarshaling to convert to map
	// This ensures consistent conversion of all types including time.Time
	data, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	return m, nil
}

// ConvertRequestAttributesToMap converts RequestAttributes to a map[string]any for CEL evaluation
func ConvertRequestAttributesToMap(attrs *request.RequestAttributes) (map[string]any, error) {
	if attrs == nil {
		return nil, nil
	}

	// Use JSON marshaling/unmarshaling to convert to map
	data, err := json.Marshal(attrs)
	if err != nil {
		return nil, err
	}

	var m map[string]any
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	return m, nil
}

// CreateValidatorFilterActivation creates a CEL activation map for validator filtering
func CreateValidatorFilterActivation(actor *Result, validatorName string, requestAttrs *request.RequestAttributes) (map[string]any, error) {
	actorMap, err := ConvertResultToMap(actor)
	if err != nil {
		return nil, err
	}

	requestMap, err := ConvertRequestAttributesToMap(requestAttrs)
	if err != nil {
		return nil, err
	}

	return map[string]any{
		"actor":          actorMap,
		"validator_name": validatorName,
		"request":        requestMap,
	}, nil
}

// CelValidatorFilter uses CEL expressions to filter validators based on actor context
type CelValidatorFilter struct {
	program cel.Program
	script  string
}

// NewCelValidatorFilter creates a new CEL-based validator filter
// The script should be a CEL expression that evaluates to a boolean
// It has access to:
//   - actor: the actor's Result object as a map (subject, issuer, trust_domain, claims, etc.)
//   - validator_name: the name of the validator being checked
//   - request: the request attributes as a map (method, path, headers, additional, etc.)
func NewCelValidatorFilter(script string) (*CelValidatorFilter, error) {
	if script == "" {
		return nil, fmt.Errorf("CEL filter script cannot be empty")
	}

	// Compile the filter script
	env, err := cel.NewEnv(ValidatorFilterLibrary())
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	ast, issues := env.Compile(script)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("failed to compile CEL filter script: %w", issues.Err())
	}

	program, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL program: %w", err)
	}

	return &CelValidatorFilter{
		program: program,
		script:  script,
	}, nil
}

// IsAllowed implements the ValidatorFilter interface
func (f *CelValidatorFilter) IsAllowed(actor *Result, validatorName string, requestAttrs *request.RequestAttributes) (bool, error) {
	activation, err := CreateValidatorFilterActivation(actor, validatorName, requestAttrs)
	if err != nil {
		return false, err
	}

	result, _, err := f.program.Eval(activation)
	if err != nil {
		return false, err
	}

	// Convert result to boolean
	if result.Type() == types.BoolType {
		return result.Value().(bool), nil
	}

	return false, nil
}

// Script returns the CEL script used by this filter
func (f *CelValidatorFilter) Script() string {
	return f.script
}
