package mapper

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	lua "github.com/yuin/gopher-lua"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/clock"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

const mapFuncName = "map"

// LuaMapper is a ClaimMapper that executes a Lua map(input) function.
// The script is compiled once at construction; each Map call loads
// the bytecode into a fresh LState.
type LuaMapper struct {
	name  string
	proto *lua.FunctionProto
	clock clock.Clock
}

type luaMapperConfig struct {
	clock clock.Clock
}

// LuaMapperOption configures a LuaMapper.
type LuaMapperOption func(*luaMapperConfig)

// WithLuaMapperClock sets the clock used by now_ms().
func WithLuaMapperClock(clk clock.Clock) LuaMapperOption {
	return func(cfg *luaMapperConfig) {
		cfg.clock = clk
	}
}

// NewLuaMapper compiles a Lua script and validates it defines a map() function.
func NewLuaMapper(name, script string, opts ...LuaMapperOption) (*LuaMapper, error) {
	if name == "" {
		return nil, fmt.Errorf("mapper name is required")
	}
	if script == "" {
		return nil, fmt.Errorf("script is required")
	}

	proto, err := luaservices.CompileScript(script, name)
	if err != nil {
		return nil, err
	}
	if err := luaservices.ValidateFunction(proto, mapFuncName); err != nil {
		return nil, err
	}

	cfg := &luaMapperConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.clock == nil {
		cfg.clock = clock.NewSystemClock()
	}

	return &LuaMapper{
		name:  name,
		proto: proto,
		clock: cfg.clock,
	}, nil
}

// Map implements service.ClaimMapper.
func (m *LuaMapper) Map(ctx context.Context, input *service.MapperInput) (service.MappingResult, error) {
	if input == nil {
		return service.MappingResult{}, fmt.Errorf("mapper input cannot be nil")
	}

	L := lua.NewState()
	defer L.Close()

	jsonService := luaservices.NewJSONService()
	jsonService.Register(L)

	clockService := luaservices.NewClockService(m.clock)
	clockService.Register(L)

	registerDatasourceService(ctx, L, input)
	registerAbortHelpers(L)

	if err := luaservices.LoadProto(L, m.proto); err != nil {
		return service.MappingResult{}, fmt.Errorf("failed to load script: %w", err)
	}

	inputTable := mapperInputToLuaTable(L, input)

	fn := L.GetGlobal(mapFuncName)
	if err := L.CallByParam(lua.P{
		Fn:      fn,
		NRet:    1,
		Protect: true,
	}, inputTable); err != nil {
		return parseLuaError(err)
	}

	ret := L.Get(-1)
	L.Pop(1)

	if ret.Type() == lua.LTNil {
		return service.AllowResult(nil), nil
	}
	if ret.Type() != lua.LTTable {
		return service.MappingResult{}, fmt.Errorf("map function must return a table or nil, got %s", ret.Type())
	}

	goVal := luaservices.LuaToGo(ret)
	resultMap, ok := goVal.(map[string]any)
	if !ok {
		return service.MappingResult{}, fmt.Errorf("map function must return a table, got %T", goVal)
	}

	return service.AllowResult(claims.Claims(resultMap)), nil
}

const abortPrefix = "__abort:"

// parseLuaError converts Lua errors raised by abort helpers into
// MappingResult deny decisions, and fail() errors into MappingFailure.
func parseLuaError(err error) (service.MappingResult, error) {
	msg := err.Error()

	// Lua errors have the form "scriptname:line: message\nstack traceback:..."
	// Find the abort prefix after the first ": " (colon-space after line number).
	idx := strings.Index(msg, abortPrefix)
	if idx < 0 {
		// Not an abort — check for __fail: prefix
		failIdx := strings.Index(msg, "__fail:")
		if failIdx >= 0 {
			detail := msg[failIdx+len("__fail:"):]
			if nl := strings.Index(detail, "\n"); nl >= 0 {
				detail = detail[:nl]
			}
			return service.MappingResult{}, &service.MappingFailure{Message: detail}
		}
		return service.MappingResult{}, fmt.Errorf("script execution failed: %w", err)
	}

	detail := msg[idx+len(abortPrefix):]
	if nl := strings.Index(detail, "\n"); nl >= 0 {
		detail = detail[:nl]
	}

	// detail is "reason:message"
	parts := strings.SplitN(detail, ":", 2)
	if len(parts) != 2 {
		return service.MappingResult{}, fmt.Errorf("malformed abort: %s", detail)
	}

	reason := service.AbortReason(parts[0])
	message := parts[1]

	return service.DenyReason(reason, message), nil
}

// registerAbortHelpers registers global functions that Lua scripts call
// to signal denials or failures. Each raises a Lua error with a structured
// prefix that parseLuaError converts back to Go types.
func registerAbortHelpers(L *lua.LState) {
	register := func(name, prefix string) {
		L.SetGlobal(name, L.NewFunction(func(L *lua.LState) int {
			msg := L.CheckString(1)
			L.RaiseError("%s%s:%s", prefix, name, msg)
			return 0
		}))
	}
	register("invalid_subject", abortPrefix)
	register("invalid_actor", abortPrefix)
	register("invalid_audience", abortPrefix)
	register("unsupported_token_type", abortPrefix)

	L.SetGlobal("fail", L.NewFunction(func(L *lua.LState) int {
		msg := L.CheckString(1)
		L.RaiseError("__fail:%s", msg)
		return 0
	}))
}

// registerDatasourceService registers a datasource table with a get(name)
// function. This is inline rather than in internal/lua to avoid an import
// cycle (internal/lua cannot import internal/service).
func registerDatasourceService(ctx context.Context, L *lua.LState, input *service.MapperInput) {
	mod := L.NewTable()
	L.SetField(mod, "get", L.NewFunction(func(L *lua.LState) int {
		name := L.CheckString(1)

		if input.DataSourceRegistry == nil {
			L.Push(L.NewTable())
			return 1
		}

		ds := input.DataSourceRegistry.Get(name)
		if ds == nil {
			L.Push(L.NewTable())
			return 1
		}

		result, err := ds.Fetch(ctx, input.DataSourceInput)
		if err != nil {
			L.RaiseError("datasource fetch failed for %s: %s", name, err.Error())
			return 0
		}
		if result == nil {
			L.Push(L.NewTable())
			return 1
		}

		var goVal any
		if err := json.Unmarshal(result.Data, &goVal); err != nil {
			L.RaiseError("datasource unmarshal failed for %s: %s", name, err.Error())
			return 0
		}

		L.Push(luaservices.GoToLua(L, goVal))
		return 1
	}))
	L.SetGlobal("datasource", mod)
}

func mapperInputToLuaTable(L *lua.LState, input *service.MapperInput) *lua.LTable {
	tbl := L.NewTable()

	if input.Subject != nil {
		L.SetField(tbl, "subject", trustResultToLuaTable(L, input.Subject))
	}
	if input.Actor != nil {
		L.SetField(tbl, "actor", trustResultToLuaTable(L, input.Actor))
	}

	return tbl
}

func trustResultToLuaTable(L *lua.LState, r *trust.Result) *lua.LTable {
	tbl := L.NewTable()
	L.SetField(tbl, "subject", lua.LString(r.Subject))
	L.SetField(tbl, "issuer", lua.LString(r.Issuer))
	L.SetField(tbl, "trust_domain", lua.LString(r.TrustDomain))

	if len(r.Claims) > 0 {
		L.SetField(tbl, "claims", luaservices.GoToLua(L, map[string]any(r.Claims)))
	}

	if len(r.Audience) > 0 {
		audTbl := L.NewTable()
		for i, a := range r.Audience {
			audTbl.RawSetInt(i+1, lua.LString(a))
		}
		L.SetField(tbl, "audience", audTbl)
	}

	if r.Scope != "" {
		L.SetField(tbl, "scope", lua.LString(r.Scope))
	}

	return tbl
}
