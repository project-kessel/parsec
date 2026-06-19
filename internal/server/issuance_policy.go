package server

import (
	"context"
	"errors"
	"fmt"
	"regexp"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// ErrIssuanceDenied is the sentinel returned by policies that deny issuance.
var ErrIssuanceDenied = errors.New("issuance denied by policy")

// IssuanceDecision carries the policy's decision to proceed with token issuance.
// A nil *IssuanceDecision (with nil error) means passthrough without issuing tokens.
type IssuanceDecision struct {
	TokenTypes []service.TokenType
	Scope      string
}

// IssuancePolicy evaluates whether token issuance should proceed, be denied,
// or be skipped (passthrough) for a given request.
//
// Return semantics:
//   - (*IssuanceDecision, nil)  -- proceed with issuance using the returned token types and scope
//   - (nil, nil)                -- passthrough; allow the request without issuing tokens
//   - (nil, err)                -- deny the request
type IssuancePolicy interface {
	Evaluate(ctx context.Context, subject, actor *trust.Result, reqAttrs *request.RequestAttributes) (*IssuanceDecision, error)
}

// AlwaysIssuePolicy is the default policy that unconditionally proceeds with
// issuance using the configured token types and empty scope. This preserves
// the pre-policy behavior.
type AlwaysIssuePolicy struct {
	tokenTypes []service.TokenType
}

// NewAlwaysIssuePolicy creates a policy that always issues with the given token types.
func NewAlwaysIssuePolicy(tokenTypes []service.TokenType) *AlwaysIssuePolicy {
	return &AlwaysIssuePolicy{tokenTypes: tokenTypes}
}

func (p *AlwaysIssuePolicy) Evaluate(_ context.Context, _, _ *trust.Result, _ *request.RequestAttributes) (*IssuanceDecision, error) {
	return &IssuanceDecision{
		TokenTypes: p.tokenTypes,
	}, nil
}

// issuancePolicyLibrary creates the CEL library for issuance policy evaluation.
func issuancePolicyLibrary() cel.EnvOption {
	return cel.Lib(&issuancePolicyLib{})
}

type issuancePolicyLib struct{}

func (lib *issuancePolicyLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Variable("subject", cel.DynType),
		cel.Variable("actor", cel.DynType),
		cel.Variable("request", cel.DynType),
	}
}

func (lib *issuancePolicyLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

// CelIssuancePolicy evaluates a CEL expression to decide whether to issue
// tokens, deny, or passthrough. The expression has access to `subject`,
// `actor`, and `request` variables.
//
// Return value interpretation:
//   - true (bool)                              -> issue with defaults
//   - false (bool)                             -> deny
//   - {"passthrough": true}                    -> passthrough
//   - {"token_types": [...], "scope": "..."}   -> issue with overrides
type CelIssuancePolicy struct {
	program      cel.Program
	script       string
	defaultTypes []service.TokenType
	defaultScope string
}

// NewCelIssuancePolicy compiles the CEL script and returns a reusable policy.
func NewCelIssuancePolicy(script string, defaultTypes []service.TokenType, defaultScope string) (*CelIssuancePolicy, error) {
	if script == "" {
		return nil, fmt.Errorf("issuance policy CEL script cannot be empty")
	}

	env, err := cel.NewEnv(issuancePolicyLibrary())
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL environment: %w", err)
	}

	ast, issues := env.Compile(script)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("failed to compile issuance policy CEL script: %w", issues.Err())
	}

	program, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("failed to create CEL program: %w", err)
	}

	return &CelIssuancePolicy{
		program:      program,
		script:       script,
		defaultTypes: defaultTypes,
		defaultScope: defaultScope,
	}, nil
}

func (p *CelIssuancePolicy) Evaluate(_ context.Context, subject, actor *trust.Result, reqAttrs *request.RequestAttributes) (*IssuanceDecision, error) {
	subjectMap, err := trust.ConvertResultToMap(subject)
	if err != nil {
		return nil, fmt.Errorf("converting subject to map: %w", err)
	}

	actorMap, err := trust.ConvertResultToMap(actor)
	if err != nil {
		return nil, fmt.Errorf("converting actor to map: %w", err)
	}

	requestMap, err := trust.ConvertRequestAttributesToMap(reqAttrs)
	if err != nil {
		return nil, fmt.Errorf("converting request to map: %w", err)
	}

	activation := map[string]any{
		"subject": subjectMap,
		"actor":   actorMap,
		"request": requestMap,
	}

	result, _, err := p.program.Eval(activation)
	if err != nil {
		return nil, fmt.Errorf("CEL evaluation failed: %w", err)
	}

	return p.interpretResult(result)
}

func (p *CelIssuancePolicy) interpretResult(result ref.Val) (*IssuanceDecision, error) {
	switch result.Type() {
	case types.BoolType:
		if result.Value().(bool) {
			return &IssuanceDecision{
				TokenTypes: p.defaultTypes,
				Scope:      p.defaultScope,
			}, nil
		}
		return nil, ErrIssuanceDenied

	case types.MapType:
		m, ok := result.Value().(map[ref.Val]ref.Val)
		if !ok {
			return nil, fmt.Errorf("CEL map result has unexpected Go type %T", result.Value())
		}
		return p.interpretMapResult(m)

	default:
		return nil, fmt.Errorf("issuance policy CEL expression must return bool or map, got %s", result.Type())
	}
}

func (p *CelIssuancePolicy) interpretMapResult(m map[ref.Val]ref.Val) (*IssuanceDecision, error) {
	if pt, ok := m[types.String("passthrough")]; ok {
		if pt.Type() == types.BoolType && pt.Value().(bool) {
			return nil, nil
		}
	}

	decision := &IssuanceDecision{
		TokenTypes: p.defaultTypes,
		Scope:      p.defaultScope,
	}

	if tokenTypesVal, ok := m[types.String("token_types")]; ok {
		list, ok := tokenTypesVal.Value().([]ref.Val)
		if !ok {
			return nil, fmt.Errorf("token_types must be a list of strings")
		}
		tokenTypes := make([]service.TokenType, 0, len(list))
		for _, v := range list {
			if v.Type() != types.StringType {
				return nil, fmt.Errorf("token_types must contain strings, got %s", v.Type())
			}
			tokenTypes = append(tokenTypes, service.TokenType(v.Value().(string)))
		}
		decision.TokenTypes = tokenTypes
	}

	if scopeVal, ok := m[types.String("scope")]; ok {
		if scopeVal.Type() != types.StringType {
			return nil, fmt.Errorf("scope must be a string, got %s", scopeVal.Type())
		}
		decision.Scope = scopeVal.Value().(string)
	}

	return decision, nil
}

// Script returns the CEL script used by this policy.
func (p *CelIssuancePolicy) Script() string {
	return p.script
}

// PathPatternOutcome defines the action when a path pattern matches.
type PathPatternOutcome string

const (
	OutcomePassthrough PathPatternOutcome = "passthrough"
	OutcomeDeny        PathPatternOutcome = "deny"
)

// PathPattern is a compiled regex pattern with a fixed outcome.
type PathPattern struct {
	regex   *regexp.Regexp
	outcome PathPatternOutcome
}

// PathPassthroughPolicy matches the request path against a set of regex
// patterns, each with a fixed outcome (passthrough or deny). If no pattern
// matches, the policy proceeds with default issuance.
type PathPassthroughPolicy struct {
	patterns     []PathPattern
	defaultTypes []service.TokenType
	defaultScope string
}

// NewPathPassthroughPolicy compiles the patterns and returns a policy.
func NewPathPassthroughPolicy(patterns []PathPatternRule, defaultTypes []service.TokenType, defaultScope string) (*PathPassthroughPolicy, error) {
	compiled := make([]PathPattern, 0, len(patterns))
	for _, rule := range patterns {
		re, err := regexp.Compile(rule.Path)
		if err != nil {
			return nil, fmt.Errorf("invalid path pattern %q: %w", rule.Path, err)
		}
		outcome := PathPatternOutcome(rule.Outcome)
		if outcome != OutcomePassthrough && outcome != OutcomeDeny {
			return nil, fmt.Errorf("invalid outcome %q for pattern %q: must be %q or %q",
				rule.Outcome, rule.Path, OutcomePassthrough, OutcomeDeny)
		}
		compiled = append(compiled, PathPattern{regex: re, outcome: outcome})
	}

	return &PathPassthroughPolicy{
		patterns:     compiled,
		defaultTypes: defaultTypes,
		defaultScope: defaultScope,
	}, nil
}

// PathPatternRule is the input for constructing a PathPassthroughPolicy.
type PathPatternRule struct {
	Path    string
	Outcome string
}

func (p *PathPassthroughPolicy) Evaluate(_ context.Context, _, _ *trust.Result, reqAttrs *request.RequestAttributes) (*IssuanceDecision, error) {
	if reqAttrs == nil {
		return &IssuanceDecision{
			TokenTypes: p.defaultTypes,
			Scope:      p.defaultScope,
		}, nil
	}

	path, ok := request.ParseMatchPath(reqAttrs.Path)
	if !ok {
		return &IssuanceDecision{
			TokenTypes: p.defaultTypes,
			Scope:      p.defaultScope,
		}, nil
	}

	for _, pat := range p.patterns {
		if pat.regex.MatchString(path) {
			switch pat.outcome {
			case OutcomePassthrough:
				return nil, nil
			case OutcomeDeny:
				return nil, ErrIssuanceDenied
			}
		}
	}

	return &IssuanceDecision{
		TokenTypes: p.defaultTypes,
		Scope:      p.defaultScope,
	}, nil
}
