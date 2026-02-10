package cel

import (
	"context"
	"encoding/json"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"

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
//   - subject, actor, request - variables containing identity and request data
//
// Pass nil for registry to create a test/validation environment.
func MapperInputLibrary(ctx context.Context, registry *service.DataSourceRegistry, dsInput *service.DataSourceInput) cel.EnvOption {
	return cel.Lib(&mapperInputLib{
		ctx:      ctx,
		registry: registry,
		dsInput:  dsInput,
		cache:    make(map[string]any),
	})
}

type mapperInputLib struct {
	ctx      context.Context
	registry *service.DataSourceRegistry
	dsInput  *service.DataSourceInput
	cache    map[string]any
}

func (lib *mapperInputLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		// Declare datasource as a function
		cel.Function("datasource",
			cel.Overload("datasource_string",
				[]*cel.Type{cel.StringType},
				cel.DynType,
				cel.UnaryBinding(lib.fetchDatasource),
			),
		),
		// Declare other variables as dynamic types
		cel.Variable("subject", cel.DynType),
		cel.Variable("actor", cel.DynType),
		cel.Variable("request", cel.DynType),
	}
}

func (lib *mapperInputLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
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

// ConvertCELValue converts a CEL ref.Val to a Go native value
func ConvertCELValue(val ref.Val) any {
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
