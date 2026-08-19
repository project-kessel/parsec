package cel

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/service"
)

// DataSourceRegistry is the interface for accessing data sources
// This matches the issuer.DataSourceRegistry interface
type DataSourceRegistry interface {
	Get(name string) service.DataSource
}

// MapperInputLibrary creates a CEL library with custom functions for accessing mapper input data.
//
// This provides compile-time declarations for:
//   - datasource(name) - function to fetch data from a named data source
//   - now_ms() - current Unix time in milliseconds (wall clock at evaluation)
//   - fail(message) - unexpected mapping/system failure (Map returns error)
//   - Layer A OAuth abort helpers (invalidRequest, invalidTarget, …) → Deny decision
//   - Layer B reason helpers (invalidSubject, invalidActor, …) → Deny decision
//   - subject, actor, request - variables containing identity and request data
//
// Pass nil for registry to create a test/validation environment.
// Pass nil for clk to use the system clock.
func MapperInputLibrary(ctx context.Context, registry *service.DataSourceRegistry, dsInput *service.DataSourceInput, clk clock.Clock) cel.EnvOption {
	return cel.Lib(&mapperInputLib{
		ctx:      ctx,
		registry: registry,
		dsInput:  dsInput,
		cache:    make(map[string]any),
		clock:    clk,
	})
}

type mapperInputLib struct {
	ctx      context.Context
	registry *service.DataSourceRegistry
	dsInput  *service.DataSourceInput
	cache    map[string]any
	clock    clock.Clock
}

func (lib *mapperInputLib) CompileOptions() []cel.EnvOption {
	opts := []cel.EnvOption{
		cel.Function("datasource",
			cel.Overload("datasource_string",
				[]*cel.Type{cel.StringType},
				cel.DynType,
				cel.UnaryBinding(lib.fetchDatasource),
			),
		),
		cel.Function("now_ms",
			cel.Overload("now_ms",
				[]*cel.Type{},
				cel.IntType,
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					return types.Int(lib.clock.Now().UnixMilli())
				}),
			),
		),
		cel.Function("fail",
			cel.Overload("fail_string",
				[]*cel.Type{cel.StringType},
				cel.DynType,
				cel.UnaryBinding(mappingFail),
			),
		),
		cel.Variable("subject", cel.DynType),
		cel.Variable("actor", cel.DynType),
		cel.Variable("request", cel.DynType),
	}
	opts = append(opts, oauthAbortFunctions()...)
	return opts
}

func (lib *mapperInputLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

// oauthAbortFunctions registers Layer A (direct OAuth codes) and Layer B
// (reason helpers) abort functions for claim-mapper CEL scripts.
// OAuth knowledge lives in service.DenyOAuth / DenyReason; CEL only binds names.
func oauthAbortFunctions() []cel.EnvOption {
	type abortSpec struct {
		name string
		deny func(message string) service.MappingResult
	}
	specs := []abortSpec{
		// Layer A — direct OAuth / token-exchange error codes
		{"invalidRequest", func(m string) service.MappingResult { return service.DenyOAuth(service.OAuthInvalidRequest, m) }},
		{"invalidTarget", func(m string) service.MappingResult { return service.DenyOAuth(service.OAuthInvalidTarget, m) }},
		{"invalidGrant", func(m string) service.MappingResult { return service.DenyOAuth(service.OAuthInvalidGrant, m) }},
		{"unauthorizedClient", func(m string) service.MappingResult { return service.DenyOAuth(service.OAuthUnauthorizedClient, m) }},
		{"invalidClient", func(m string) service.MappingResult { return service.DenyOAuth(service.OAuthInvalidClient, m) }},
		{"unsupportedGrantType", func(m string) service.MappingResult { return service.DenyOAuth(service.OAuthUnsupportedGrantType, m) }},
		{"invalidScope", func(m string) service.MappingResult { return service.DenyOAuth(service.OAuthInvalidScope, m) }},
		// accessDenied: policy-level denial (RFC 6749 §4.1.2.1) → HTTP 403 in
		// ext_authz. Use for access-control policies (e.g. export compliance)
		// that are not OAuth protocol errors.
		{"accessDenied", func(m string) service.MappingResult { return service.DenyOAuth(service.OAuthAccessDenied, m) }},
		// Layer B — reason helpers (reason→code mapping lives in service)
		{"invalidSubject", func(m string) service.MappingResult { return service.DenyReason(service.AbortReasonInvalidSubject, m) }},
		{"invalidActor", func(m string) service.MappingResult { return service.DenyReason(service.AbortReasonInvalidActor, m) }},
		{"invalidAudience", func(m string) service.MappingResult { return service.DenyReason(service.AbortReasonInvalidAudience, m) }},
		{"unsupportedTokenType", func(m string) service.MappingResult {
			return service.DenyReason(service.AbortReasonUnsupportedTokenType, m)
		}},
	}

	opts := make([]cel.EnvOption, 0, len(specs))
	for _, spec := range specs {
		name, deny := spec.name, spec.deny
		opts = append(opts, cel.Function(name,
			cel.Overload(name+"_string",
				[]*cel.Type{cel.StringType},
				cel.DynType,
				cel.UnaryBinding(mappingAbort(deny)),
			),
		))
	}
	return opts
}

// fetchDatasource implements the datasource() CEL function
func (lib *mapperInputLib) fetchDatasource(arg ref.Val) ref.Val {
	name, ok := arg.Value().(string)
	if !ok {
		return types.NewErr("datasource argument must be a string")
	}

	// Check cache first
	if cached, ok := lib.cache[name]; ok {
		return types.DefaultTypeAdapter.NativeToValue(cached)
	}

	// If no registry (test mode), return null
	if lib.registry == nil {
		return types.NullValue
	}

	// Get the datasource
	ds := lib.registry.Get(name)
	if ds == nil {
		return types.NullValue
	}

	// Fetch the data
	result, err := ds.Fetch(lib.ctx, lib.dsInput)
	if err != nil {
		// Return error as CEL error - using fmt.Errorf for proper formatting
		return types.WrapErr(err)
	}

	if result == nil {
		return types.NullValue
	}

	// Deserialize based on content type
	switch result.ContentType {
	case service.ContentTypeJSON:
		var data any
		if err := json.Unmarshal(result.Data, &data); err != nil {
			// Return error as CEL error
			return types.WrapErr(err)
		}

		// Cache the result
		lib.cache[name] = data
		return types.DefaultTypeAdapter.NativeToValue(data)
	default:
		// Return simple error for unsupported type
		return types.NewErr("unsupported content type")
	}
}

func mappingFail(arg ref.Val) ref.Val {
	msg, ok := arg.Value().(string)
	if !ok {
		return types.NewErr("fail argument must be a string")
	}
	return types.WrapErr(&service.MappingFailure{Message: msg})
}

// abortError carries a MappingDecision for CEL abort helpers.
// It is distinct from fail() MappingFailure — AbortDecision extracts it.
type abortError struct {
	decision service.MappingDecision
}

func (e *abortError) Error() string { return e.decision.Message }

func mappingAbort(deny func(message string) service.MappingResult) func(ref.Val) ref.Val {
	return func(arg ref.Val) ref.Val {
		msg, ok := arg.Value().(string)
		if !ok {
			return types.NewErr("abort argument must be a string")
		}
		return types.WrapErr(&abortError{decision: deny(msg).Decision})
	}
}

// AbortDecision extracts a MappingDecision from a CEL abort error.
// Returns false for fail()-style MappingFailure and any other unexpected errors.
func AbortDecision(err error) (service.MappingDecision, bool) {
	var ae *abortError
	if errors.As(err, &ae) {
		return ae.decision, true
	}
	return service.MappingDecision{}, false
}

// UnwrapMappingFailure extracts a *service.MappingFailure from a CEL eval error
// chain (fail()). Returns nil for abort decisions and other errors.
func UnwrapMappingFailure(err error) *service.MappingFailure {
	var mf *service.MappingFailure
	if errors.As(err, &mf) {
		return mf
	}
	return nil
}

// ConvertCELValue converts a CEL ref.Val to a Go native value
func ConvertCELValue(val ref.Val) any {
	if val.Type() == types.NullType {
		return nil
	}

	// First try the simple conversion
	nativeVal := val.Value()

	// Check if it's a map[ref.Val]ref.Val (CEL's internal map representation)
	if m, ok := nativeVal.(map[ref.Val]ref.Val); ok {
		result := make(map[string]any)
		for k, v := range m {
			if keyStr, ok := k.Value().(string); ok {
				result[keyStr] = ConvertCELValue(v)
			}
		}
		return result
	}

	// Check if it's a slice that needs conversion
	if slice, ok := nativeVal.([]any); ok {
		result := make([]any, len(slice))
		for i, item := range slice {
			if refVal, ok := item.(ref.Val); ok {
				result[i] = ConvertCELValue(refVal)
			} else {
				result[i] = item
			}
		}
		return result
	}

	// Check if it's already a map[string]any
	if m, ok := nativeVal.(map[string]any); ok {
		// Still need to convert any nested ref.Val values
		result := make(map[string]any)
		for k, v := range m {
			if refVal, ok := v.(ref.Val); ok {
				result[k] = ConvertCELValue(refVal)
			} else {
				result[k] = v
			}
		}
		return result
	}

	return nativeVal
}
