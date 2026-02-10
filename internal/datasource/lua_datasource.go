package datasource

import (
	"context"
	"fmt"
	"time"

	lua "github.com/yuin/gopher-lua"

	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// LuaDataSource executes a Lua script to fetch data
// The script has access to http, config, and json services
type LuaDataSource struct {
	name         string
	script       string
	configSource luaservices.ConfigSource
	httpConfig   luaservices.HTTPServiceConfig
}

// LuaDataSourceConfig configures a Lua data source
type LuaDataSourceConfig struct {
	// Name identifies this data source
	Name string

	// Script is the Lua script to execute
	// The script should define a function called 'fetch' that takes an input table
	// and returns a result table with 'data' and 'content_type' fields
	//
	// Example:
	//   function fetch(input)
	//     local response = http.get("https://api.example.com/user/" .. input.subject.subject)
	//     if response.status == 200 then
	//       return {data = response.body, content_type = "application/json"}
	//     end
	//     return nil
	//   end
	Script string

	// ConfigSource provides configuration values available to the script via config.get()
	// If nil, an empty MapConfigSource will be used
	ConfigSource luaservices.ConfigSource

	// HTTPConfig provides HTTP service configuration including timeout, fixtures, etc.
	// If nil, default HTTP config (30s timeout, no fixtures) will be used
	HTTPConfig *luaservices.HTTPServiceConfig
}

// NewLuaDataSource creates a new Lua data source
func NewLuaDataSource(config LuaDataSourceConfig) (*LuaDataSource, error) {
	if config.Name == "" {
		return nil, fmt.Errorf("data source name is required")
	}
	if config.Script == "" {
		return nil, fmt.Errorf("script is required")
	}

	if config.ConfigSource == nil {
		config.ConfigSource = luaservices.NewMapConfigSource(nil)
	}

	// Validate that the script has a fetch function
	L := lua.NewState()
	defer L.Close()

	if err := L.DoString(config.Script); err != nil {
		return nil, fmt.Errorf("failed to load script: %w", err)
	}

	fetchFunc := L.GetGlobal("fetch")
	if fetchFunc.Type() != lua.LTFunction {
		return nil, fmt.Errorf("script must define a 'fetch' function")
	}

	// Build HTTP config with defaults if not provided
	var httpConfig luaservices.HTTPServiceConfig
	if config.HTTPConfig != nil {
		httpConfig = *config.HTTPConfig
	} else {
		// Default: 30 second timeout, no fixtures
		httpConfig = luaservices.HTTPServiceConfig{
			Timeout: 30 * time.Second,
		}
	}

	return &LuaDataSource{
		name:         config.Name,
		script:       config.Script,
		configSource: config.ConfigSource,
		httpConfig:   httpConfig,
	}, nil
}

// Name returns the data source name
func (ds *LuaDataSource) Name() string {
	return ds.name
}

// Fetch executes the Lua script to fetch data
func (ds *LuaDataSource) Fetch(ctx context.Context, input *service.DataSourceInput) (*service.DataSourceResult, error) {
	// Create a new Lua state for this request
	L := lua.NewState()
	defer L.Close()

	// Register services
	httpService := luaservices.NewHTTPServiceWithConfig(ds.httpConfig)
	httpService.Register(L)

	configService := luaservices.NewConfigService(ds.configSource)
	configService.Register(L)

	jsonService := luaservices.NewJSONService()
	jsonService.Register(L)

	// Load the script
	if err := L.DoString(ds.script); err != nil {
		return nil, fmt.Errorf("failed to load script: %w", err)
	}

	// Convert input to Lua table
	inputTable := ds.inputToLuaTable(L, input)

	// Call the fetch function
	fetchFunc := L.GetGlobal("fetch")
	if err := L.CallByParam(lua.P{
		Fn:      fetchFunc,
		NRet:    1,
		Protect: true,
	}, inputTable); err != nil {
		return nil, fmt.Errorf("script execution failed: %w", err)
	}

	// Get the result
	ret := L.Get(-1)
	L.Pop(1)

	// Handle nil result (data source has nothing to contribute)
	if ret.Type() == lua.LTNil {
		return nil, nil
	}

	// Convert result to DataSourceResult
	if ret.Type() != lua.LTTable {
		return nil, fmt.Errorf("fetch function must return a table or nil, got %s", ret.Type())
	}

	resultTable := ret.(*lua.LTable)
	return ds.luaTableToResult(resultTable)
}

// inputToLuaTable converts a DataSourceInput to a Lua table
func (ds *LuaDataSource) inputToLuaTable(L *lua.LState, input *service.DataSourceInput) *lua.LTable {
	tbl := L.NewTable()

	if input.Subject != nil {
		subjectTbl := L.NewTable()
		L.SetField(subjectTbl, "subject", lua.LString(input.Subject.Subject))
		L.SetField(subjectTbl, "issuer", lua.LString(input.Subject.Issuer))

		if len(input.Subject.Claims) > 0 {
			claimsTbl := L.NewTable()
			for key, value := range input.Subject.Claims {
				claimsTbl.RawSetString(key, luaservices.GoToLua(L, value))
			}
			L.SetField(subjectTbl, "claims", claimsTbl)
		}

		L.SetField(tbl, "subject", subjectTbl)
	}

	if input.Actor != nil {
		actorTbl := L.NewTable()
		L.SetField(actorTbl, "subject", lua.LString(input.Actor.Subject))
		L.SetField(actorTbl, "issuer", lua.LString(input.Actor.Issuer))

		if len(input.Actor.Claims) > 0 {
			claimsTbl := L.NewTable()
			for key, value := range input.Actor.Claims {
				claimsTbl.RawSetString(key, luaservices.GoToLua(L, value))
			}
			L.SetField(actorTbl, "claims", claimsTbl)
		}

		L.SetField(tbl, "actor", actorTbl)
	}

	if input.RequestAttributes != nil {
		reqTbl := L.NewTable()
		if input.RequestAttributes.Method != "" {
			L.SetField(reqTbl, "method", lua.LString(input.RequestAttributes.Method))
		}
		if input.RequestAttributes.Path != "" {
			L.SetField(reqTbl, "path", lua.LString(input.RequestAttributes.Path))
		}
		if input.RequestAttributes.IPAddress != "" {
			L.SetField(reqTbl, "ip_address", lua.LString(input.RequestAttributes.IPAddress))
		}
		if input.RequestAttributes.UserAgent != "" {
			L.SetField(reqTbl, "user_agent", lua.LString(input.RequestAttributes.UserAgent))
		}

		if len(input.RequestAttributes.Headers) > 0 {
			headersTbl := L.NewTable()
			for key, value := range input.RequestAttributes.Headers {
				headersTbl.RawSetString(key, lua.LString(value))
			}
			L.SetField(reqTbl, "headers", headersTbl)
		}

		if len(input.RequestAttributes.Additional) > 0 {
			additionalTbl := L.NewTable()
			for key, value := range input.RequestAttributes.Additional {
				additionalTbl.RawSetString(key, luaservices.GoToLua(L, value))
			}
			L.SetField(reqTbl, "additional", additionalTbl)
		}

		L.SetField(tbl, "request_attributes", reqTbl)
	}

	return tbl
}

// luaTableToResult converts a Lua table to a DataSourceResult
func (ds *LuaDataSource) luaTableToResult(tbl *lua.LTable) (*service.DataSourceResult, error) {
	dataField := tbl.RawGetString("data")
	if dataField.Type() == lua.LTNil {
		return nil, fmt.Errorf("result table must have a 'data' field")
	}

	var data []byte
	switch v := dataField.(type) {
	case lua.LString:
		data = []byte(string(v))
	default:
		return nil, fmt.Errorf("'data' field must be a string")
	}

	contentTypeField := tbl.RawGetString("content_type")
	contentType := service.ContentTypeJSON // default
	if contentTypeField.Type() == lua.LTString {
		contentType = service.DataSourceContentType(lua.LVAsString(contentTypeField))
	}

	return &service.DataSourceResult{
		Data:        data,
		ContentType: contentType,
	}, nil
}

// luaTableToInput converts a Lua table to a DataSourceInput
func (ds *LuaDataSource) luaTableToInput(tbl *lua.LTable) service.DataSourceInput {
	input := service.DataSourceInput{}

	// Parse subject
	if subjectLV := tbl.RawGetString("subject"); subjectLV.Type() == lua.LTTable {
		subjectTbl := subjectLV.(*lua.LTable)
		subject := &trust.Result{
			Subject: lua.LVAsString(subjectTbl.RawGetString("subject")),
			Issuer:  lua.LVAsString(subjectTbl.RawGetString("issuer")),
		}

		if claimsLV := subjectTbl.RawGetString("claims"); claimsLV.Type() == lua.LTTable {
			subject.Claims = luaTableToMap(claimsLV.(*lua.LTable))
		}

		input.Subject = subject
	}

	// Parse actor
	if actorLV := tbl.RawGetString("actor"); actorLV.Type() == lua.LTTable {
		actorTbl := actorLV.(*lua.LTable)
		actor := &trust.Result{
			Subject: lua.LVAsString(actorTbl.RawGetString("subject")),
			Issuer:  lua.LVAsString(actorTbl.RawGetString("issuer")),
		}

		if claimsLV := actorTbl.RawGetString("claims"); claimsLV.Type() == lua.LTTable {
			actor.Claims = luaTableToMap(claimsLV.(*lua.LTable))
		}

		input.Actor = actor
	}

	// Parse request attributes
	if reqLV := tbl.RawGetString("request_attributes"); reqLV.Type() == lua.LTTable {
		reqTbl := reqLV.(*lua.LTable)
		reqAttrs := &request.RequestAttributes{
			Method:    lua.LVAsString(reqTbl.RawGetString("method")),
			Path:      lua.LVAsString(reqTbl.RawGetString("path")),
			IPAddress: lua.LVAsString(reqTbl.RawGetString("ip_address")),
			UserAgent: lua.LVAsString(reqTbl.RawGetString("user_agent")),
		}

		if headersLV := reqTbl.RawGetString("headers"); headersLV.Type() == lua.LTTable {
			headers := make(map[string]string)
			headersLV.(*lua.LTable).ForEach(func(k, v lua.LValue) {
				if k.Type() == lua.LTString && v.Type() == lua.LTString {
					headers[k.String()] = v.String()
				}
			})
			reqAttrs.Headers = headers
		}

		if additionalLV := reqTbl.RawGetString("additional"); additionalLV.Type() == lua.LTTable {
			reqAttrs.Additional = luaTableToMap(additionalLV.(*lua.LTable))
		}

		input.RequestAttributes = reqAttrs
	}

	return input
}

// luaTableToMap converts a Lua table to a Go map
func luaTableToMap(tbl *lua.LTable) map[string]interface{} {
	result := make(map[string]interface{})
	tbl.ForEach(func(k, v lua.LValue) {
		if k.Type() == lua.LTString {
			result[k.String()] = luaservices.LuaToGo(v)
		}
	})
	return result
}

// CacheableLuaDataSource is a Lua data source that implements the Cacheable interface
type CacheableLuaDataSource struct {
	*LuaDataSource
	cacheKeyFunc string
	cacheTTL     time.Duration
}

// CacheableLuaDataSourceConfig configures a cacheable Lua data source
type CacheableLuaDataSourceConfig struct {
	// Name identifies this data source
	Name string

	// Script is the Lua script to execute
	// The script should define a function called 'fetch' that takes an input table
	// and returns a result table with 'data' and 'content_type' fields
	Script string

	// ConfigSource provides configuration values available to the script via config.get()
	// If nil, an empty MapConfigSource will be used
	ConfigSource luaservices.ConfigSource

	// HTTPConfig provides HTTP service configuration including timeout, fixtures, etc.
	// If nil, default HTTP config (30s timeout, no fixtures) will be used
	HTTPConfig *luaservices.HTTPServiceConfig

	// CacheKeyFunc is the name of the Lua function that generates cache keys
	// REQUIRED - the function should take an input table and return a modified input table
	// with only the fields relevant for caching
	//
	// Example:
	//   function cache_key(input)
	//     return {subject = {subject = input.subject.subject}}
	//   end
	CacheKeyFunc string

	// CacheTTL is the cache time-to-live
	// Default: 5 minutes
	CacheTTL time.Duration
}

// NewCacheableLuaDataSource creates a new cacheable Lua data source
func NewCacheableLuaDataSource(config CacheableLuaDataSourceConfig) (*CacheableLuaDataSource, error) {
	if config.CacheKeyFunc == "" {
		return nil, fmt.Errorf("cache_key function is required for cacheable data source")
	}

	if config.CacheTTL == 0 {
		config.CacheTTL = 5 * time.Minute
	}

	// Create the base data source
	baseDS, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:         config.Name,
		Script:       config.Script,
		ConfigSource: config.ConfigSource,
		HTTPConfig:   config.HTTPConfig,
	})
	if err != nil {
		return nil, err
	}

	// Validate that the cache_key function exists
	L := lua.NewState()
	defer L.Close()

	if err := L.DoString(config.Script); err != nil {
		return nil, fmt.Errorf("failed to load script: %w", err)
	}

	cacheKeyFunc := L.GetGlobal(config.CacheKeyFunc)
	if cacheKeyFunc.Type() != lua.LTFunction {
		return nil, fmt.Errorf("script must define a '%s' function", config.CacheKeyFunc)
	}

	return &CacheableLuaDataSource{
		LuaDataSource: baseDS,
		cacheKeyFunc:  config.CacheKeyFunc,
		cacheTTL:      config.CacheTTL,
	}, nil
}

// CacheKey implements the Cacheable interface
func (ds *CacheableLuaDataSource) CacheKey(input *service.DataSourceInput) service.DataSourceInput {
	// Create a new Lua state
	L := lua.NewState()
	defer L.Close()

	// Load the script
	if err := L.DoString(ds.script); err != nil {
		// On error, return full input
		return *input
	}

	// Convert input to Lua table
	inputTable := ds.inputToLuaTable(L, input)

	// Call the cache key function
	cacheKeyFunc := L.GetGlobal(ds.cacheKeyFunc)
	if err := L.CallByParam(lua.P{
		Fn:      cacheKeyFunc,
		NRet:    1,
		Protect: true,
	}, inputTable); err != nil {
		// On error, return full input
		return *input
	}

	// Get the result
	ret := L.Get(-1)
	L.Pop(1)

	if ret.Type() != lua.LTTable {
		// On error, return full input
		return *input
	}

	// Convert result back to DataSourceInput
	maskedInput := ds.luaTableToInput(ret.(*lua.LTable))
	return maskedInput
}

// CacheTTL implements the Cacheable interface
func (ds *CacheableLuaDataSource) CacheTTL() time.Duration {
	return ds.cacheTTL
}
