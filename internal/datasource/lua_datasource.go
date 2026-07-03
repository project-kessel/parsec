package datasource

import (
	"context"
	"fmt"
	"net/http"

	lua "github.com/yuin/gopher-lua"

	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

const fetchCacheKeyFuncName = "fetch_cache_key"

// LuaDataSource executes a Lua script to fetch data.
// The script has access to http, config, and json services.
//
// The Lua script is compiled once at construction time; each call to
// [LuaDataSource.Fetch] loads the pre-compiled bytecode into a fresh
// LState, avoiding repeated parsing and compilation.
type LuaDataSource struct {
	name           string
	proto          *lua.FunctionProto
	configSource   luaservices.ConfigSource
	httpClient     *http.Client
	requestOptions luaservices.RequestOptions
	observer       LuaObserver
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

	// HTTPClient is the pre-configured HTTP client for the Lua http service.
	// If nil, http.DefaultClient will be used.
	HTTPClient *http.Client

	// RequestOptions is a programmatic hook that augments outgoing HTTP requests
	// (e.g. injecting headers or query params from Go context). Optional.
	RequestOptions luaservices.RequestOptions

	// Observer for Lua-specific execution events. If nil, defaults to NoOpObserver.
	Observer LuaObserver
}

// NewLuaDataSource creates a new Lua data source.
//
// The script is compiled once during construction; see [LuaDataSource] for
// the runtime lifecycle.
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

	proto, err := luaservices.CompileScript(config.Script, config.Name)
	if err != nil {
		return nil, err
	}
	if err := luaservices.ValidateFunction(proto, "fetch"); err != nil {
		return nil, err
	}

	obs := config.Observer
	if obs == nil {
		obs = NoOpDataSourceObserver{}
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}

	return &LuaDataSource{
		name:           config.Name,
		proto:          proto,
		configSource:   config.ConfigSource,
		httpClient:     httpClient,
		requestOptions: config.RequestOptions,
		observer:       obs,
	}, nil
}

// Name returns the data source name
func (ds *LuaDataSource) Name() string {
	return ds.name
}

// Fetch executes the Lua script to fetch data
func (ds *LuaDataSource) Fetch(ctx context.Context, input *service.DataSourceInput) (*service.DataSourceResult, error) {
	ctx, p := ds.observer.LuaFetchStarted(ctx, ds.name)
	defer p.End()

	if input == nil {
		return nil, fmt.Errorf("nil input")
	}

	L := lua.NewState()
	defer L.Close()

	var httpOpts []luaservices.HTTPServiceOption
	if ds.requestOptions != nil {
		httpOpts = append(httpOpts, luaservices.WithRequestOptions(ds.requestOptions))
	}
	httpService, err := luaservices.NewHTTPService(ctx, ds.httpClient, httpOpts...)
	if err != nil {
		p.ScriptExecutionFailed(err)
		return nil, fmt.Errorf("failed to create http service: %w", err)
	}
	httpService.Register(L)

	configService := luaservices.NewConfigService(ds.configSource)
	configService.Register(L)

	jsonService := luaservices.NewJSONService()
	jsonService.Register(L)

	if err := luaservices.LoadProto(L, ds.proto); err != nil {
		p.ScriptLoadFailed(err)
		return nil, fmt.Errorf("failed to load script: %w", err)
	}

	inputTable := ds.inputToLuaTable(L, input)

	fetchFunc := L.GetGlobal("fetch")
	if err := L.CallByParam(lua.P{
		Fn:      fetchFunc,
		NRet:    1,
		Protect: true,
	}, inputTable); err != nil {
		p.ScriptExecutionFailed(err)
		return nil, fmt.Errorf("script execution failed: %w", err)
	}

	ret := L.Get(-1)
	L.Pop(1)

	if ret.Type() == lua.LTNil {
		p.FetchCompletedNil()
		return nil, nil
	}

	if ret.Type() != lua.LTTable {
		p.InvalidReturnType(ret.Type().String())
		return nil, fmt.Errorf("fetch function must return a table or nil, got %s", ret.Type())
	}

	result, err := ds.luaTableToResult(ret.(*lua.LTable))
	if err != nil {
		p.ResultConversionFailed(err)
		return nil, err
	}
	p.FetchCompleted()
	return result, nil
}

// inputToLuaTable converts a DataSourceInput to a Lua table
func (ds *LuaDataSource) inputToLuaTable(L *lua.LState, input *service.DataSourceInput) *lua.LTable {
	tbl := L.NewTable()

	if input == nil {
		return tbl
	}

	if input.Subject != nil {
		L.SetField(tbl, "subject", ds.trustResultToLuaTable(L, input.Subject))
	}

	if input.Actor != nil {
		L.SetField(tbl, "actor", ds.trustResultToLuaTable(L, input.Actor))
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

// trustResultToLuaTable converts a trust.Result to a Lua table for script access.
func (ds *LuaDataSource) trustResultToLuaTable(L *lua.LState, result *trust.Result) *lua.LTable {
	tbl := L.NewTable()
	L.SetField(tbl, "subject", lua.LString(result.Subject))
	L.SetField(tbl, "issuer", lua.LString(result.Issuer))

	if len(result.Claims) > 0 {
		claimsTbl := L.NewTable()
		for key, value := range result.Claims {
			claimsTbl.RawSetString(key, luaservices.GoToLua(L, value))
		}
		L.SetField(tbl, "claims", claimsTbl)
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
		input.Subject = luaTableToTrustResult(subjectLV.(*lua.LTable))
	}

	// Parse actor
	if actorLV := tbl.RawGetString("actor"); actorLV.Type() == lua.LTTable {
		input.Actor = luaTableToTrustResult(actorLV.(*lua.LTable))
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

// luaTableToTrustResult converts a Lua table to a trust.Result.
func luaTableToTrustResult(tbl *lua.LTable) *trust.Result {
	result := &trust.Result{
		Subject: lua.LVAsString(tbl.RawGetString("subject")),
		Issuer:  lua.LVAsString(tbl.RawGetString("issuer")),
	}

	if claimsLV := tbl.RawGetString("claims"); claimsLV.Type() == lua.LTTable {
		result.Claims = luaTableToMap(claimsLV.(*lua.LTable))
	}

	return result
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

// CacheableLuaDataSource is a Lua data source that implements the Cacheable interface.
type CacheableLuaDataSource struct {
	*LuaDataSource
}

// CacheableLuaDataSourceConfig configures a cacheable Lua data source
type CacheableLuaDataSourceConfig struct {
	// Name identifies this data source
	Name string

	// Script is the Lua script to execute
	//
	// The script should define a function called 'fetch' that takes an input table
	// and returns a result table with 'data' and 'content_type' fields
	//
	// The script must define fetch_cache_key(input), which returns a modified input
	// table with only the fields relevant for caching.
	//
	// Example:
	//   function fetch_cache_key(input)
	//     return {subject = {subject = input.subject.subject}}
	//   end
	Script string

	// ConfigSource provides configuration values available to the script via config.get()
	// If nil, an empty MapConfigSource will be used
	ConfigSource luaservices.ConfigSource

	// HTTPClient is the pre-configured HTTP client for the Lua http service.
	// If nil, http.DefaultClient will be used.
	HTTPClient *http.Client

	// RequestOptions is a programmatic hook that augments outgoing HTTP requests. Optional.
	RequestOptions luaservices.RequestOptions

	// Observer for Lua-specific execution events on the inner Lua data source.
	// If nil, NewLuaDataSource substitutes NoOpDataSourceObserver{}.
	Observer LuaObserver
}

// NewCacheableLuaDataSource creates a new cacheable Lua data source.
func NewCacheableLuaDataSource(config CacheableLuaDataSourceConfig) (*CacheableLuaDataSource, error) {
	baseDS, err := NewLuaDataSource(LuaDataSourceConfig(config))
	if err != nil {
		return nil, err
	}

	if err := luaservices.ValidateFunction(baseDS.proto, fetchCacheKeyFuncName); err != nil {
		return nil, err
	}

	return &CacheableLuaDataSource{
		LuaDataSource: baseDS,
	}, nil
}

// CacheKey implements the Cacheable interface
func (ds *CacheableLuaDataSource) CacheKey(input *service.DataSourceInput) service.DataSourceInput {
	if input == nil {
		return service.DataSourceInput{}
	}

	L := lua.NewState()
	defer L.Close()

	configService := luaservices.NewConfigService(ds.configSource)
	configService.Register(L)

	jsonService := luaservices.NewJSONService()
	jsonService.Register(L)

	if err := luaservices.LoadProto(L, ds.proto); err != nil {
		return *input
	}

	inputTable := ds.inputToLuaTable(L, input)

	cacheKeyFunc := L.GetGlobal(fetchCacheKeyFuncName)
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
