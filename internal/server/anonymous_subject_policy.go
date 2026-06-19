package server

import (
	"context"
	"fmt"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/trust"
)

// AnonymousSubjectPolicy decides whether a request without subject credentials
// should be allowed through. Evaluated after actor extraction but before any
// subject validation.
type AnonymousSubjectPolicy interface {
	IsAllowed(ctx context.Context, actor *trust.Result, reqAttrs *request.RequestAttributes) (bool, error)
}

// DenyAllPolicy is a null-object AnonymousSubjectPolicy that unconditionally
// denies anonymous subjects. Used as the default when no policy is configured.
type DenyAllPolicy struct{}

func (DenyAllPolicy) IsAllowed(context.Context, *trust.Result, *request.RequestAttributes) (bool, error) {
	return false, nil
}

// anonymousSubjectPolicyLibrary creates the CEL library for anonymous subject
// policy evaluation, declaring `actor` and `request` variables.
func anonymousSubjectPolicyLibrary() cel.EnvOption {
	return cel.Lib(&anonPolicyLib{})
}

type anonPolicyLib struct{}

func (lib *anonPolicyLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Variable("actor", cel.DynType),
		cel.Variable("request", cel.DynType),
	}
}

func (lib *anonPolicyLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

// CelAnonymousSubjectPolicy evaluates a CEL expression to decide whether an
// anonymous (no-credential) request is allowed. The expression has access to
// `actor` (the validated actor result as a map) and `request` (the request
// attributes as a map). It must evaluate to a boolean.
type CelAnonymousSubjectPolicy struct {
	program cel.Program
	script  string
}

// NewCelAnonymousSubjectPolicy compiles the CEL script at startup and returns
// a reusable policy. Returns an error if the script is empty or fails to compile.
func NewCelAnonymousSubjectPolicy(script string) (*CelAnonymousSubjectPolicy, error) {
	if script == "" {
		return nil, fmt.Errorf("anonymous subject policy CEL script cannot be empty")
	}

	env, err := cel.NewEnv(anonymousSubjectPolicyLibrary())
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	ast, issues := env.Compile(script)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("failed to compile anonymous subject policy CEL script: %w", issues.Err())
	}

	program, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL program: %w", err)
	}

	return &CelAnonymousSubjectPolicy{
		program: program,
		script:  script,
	}, nil
}

// IsAllowed evaluates the CEL expression against the given actor and request.
// Returns false for invalid paths (encoding, traversal, double-slash) without
// evaluating the CEL expression.
func (p *CelAnonymousSubjectPolicy) IsAllowed(_ context.Context, actor *trust.Result, reqAttrs *request.RequestAttributes) (bool, error) {
	if reqAttrs == nil {
		return false, nil
	}

	validPath, ok := request.ParseMatchPath(reqAttrs.Path)
	if !ok {
		return false, nil
	}

	cleanAttrs := *reqAttrs
	cleanAttrs.Path = validPath

	// TODO: avoid JSON round-trip on hot path (health checks); use direct struct-to-map conversion
	actorMap, err := trust.ConvertResultToMap(actor)
	if err != nil {
		return false, fmt.Errorf("converting actor to map: %w", err)
	}

	requestMap, err := trust.ConvertRequestAttributesToMap(&cleanAttrs)
	if err != nil {
		return false, fmt.Errorf("converting request to map: %w", err)
	}

	activation := map[string]any{
		"actor":   actorMap,
		"request": requestMap,
	}

	result, _, err := p.program.Eval(activation)
	if err != nil {
		return false, err
	}

	if result.Type() != types.BoolType {
		return false, fmt.Errorf("anonymous subject policy CEL expression must return bool, got %s", result.Type())
	}

	return result.Value().(bool), nil
}

// Script returns the CEL script used by this policy.
func (p *CelAnonymousSubjectPolicy) Script() string {
	return p.script
}
