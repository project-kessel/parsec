package trust

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"time"

	lua "github.com/yuin/gopher-lua"

	"github.com/project-kessel/parsec/internal/claims"
	luaservices "github.com/project-kessel/parsec/internal/lua"
)

// ScriptName is the source name used when compiling Lua validator scripts.
// It appears in Lua error messages and stack traces.
type ScriptName = string

const (
	validateFuncName         = "validate"
	validateCacheKeyFuncName = "validate_cache_key"
)

// ValidatorInput is the Lua validator ABI input. It wraps a [Credential] in a
// nesting object so scripts access fields as input.credential.*. It is also
// JSON-serializable for use as distributed cache key material.
type ValidatorInput struct {
	Credential Credential
}

func (v ValidatorInput) MarshalJSON() ([]byte, error) {
	credJSON, err := MarshalCredentialJSON(v.Credential)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		Credential json.RawMessage `json:"credential"`
	}{Credential: credJSON})
}

func (v *ValidatorInput) UnmarshalJSON(data []byte) error {
	var raw struct {
		Credential json.RawMessage `json:"credential"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	cred, err := UnmarshalCredentialJSON(raw.Credential)
	if err != nil {
		return err
	}
	v.Credential = cred
	return nil
}

// LuaValidator validates credentials by executing a Lua validate(input)
// function. The script has access to http, config, and json services.
//
// The Lua script is compiled once at construction time; each call to
// [LuaValidator.Validate] loads the pre-compiled bytecode into a fresh
// LState, avoiding repeated parsing and compilation.
type LuaValidator struct {
	name            string
	proto           *lua.FunctionProto
	credentialTypes []CredentialType
	configSource    luaservices.ConfigSource
	httpClient      *http.Client
	requestOptions  luaservices.RequestOptions
	observer        LuaValidatorObserver
}

type luaValidatorConfig struct {
	configSource   luaservices.ConfigSource
	httpClient     *http.Client
	requestOptions luaservices.RequestOptions
	observer       LuaValidatorObserver
}

// LuaValidatorOption configures optional settings for Lua validators.
type LuaValidatorOption func(*luaValidatorConfig)

// WithLuaConfigSource sets the configuration source exposed as config.get().
func WithLuaConfigSource(source luaservices.ConfigSource) LuaValidatorOption {
	return func(cfg *luaValidatorConfig) {
		cfg.configSource = source
	}
}

// WithLuaHTTPClient sets the pre-configured HTTP client for the Lua http service.
func WithLuaHTTPClient(client *http.Client) LuaValidatorOption {
	return func(cfg *luaValidatorConfig) {
		cfg.httpClient = client
	}
}

// WithLuaRequestOptions sets a function that augments outgoing HTTP requests
// (e.g. injecting headers from Go context). This is independent of the HTTP
// client's transport and applies per-request.
func WithLuaRequestOptions(ro luaservices.RequestOptions) LuaValidatorOption {
	return func(cfg *luaValidatorConfig) {
		cfg.requestOptions = ro
	}
}

// WithLuaValidatorObserver sets the observer for Lua validation events.
func WithLuaValidatorObserver(observer LuaValidatorObserver) LuaValidatorOption {
	return func(cfg *luaValidatorConfig) {
		cfg.observer = observer
	}
}

// NewLuaValidator creates a Lua-backed credential validator.
//
// The script is compiled once during construction; see [LuaValidator] for
// the runtime lifecycle.
func NewLuaValidator(name ScriptName, script string, credentialTypes []CredentialType, opts ...LuaValidatorOption) (*LuaValidator, error) {
	if name == "" {
		return nil, fmt.Errorf("validator name is required")
	}
	if script == "" {
		return nil, fmt.Errorf("script is required")
	}
	if len(credentialTypes) == 0 {
		return nil, fmt.Errorf("at least one credential type is required")
	}

	proto, err := luaservices.CompileScript(script, name)
	if err != nil {
		return nil, err
	}
	if err := luaservices.ValidateFunction(proto, validateFuncName); err != nil {
		return nil, err
	}

	cfg := newLuaValidatorConfig(opts...)

	return &LuaValidator{
		name:            name,
		proto:           proto,
		credentialTypes: slices.Clone(credentialTypes),
		configSource:    cfg.configSource,
		httpClient:      cfg.httpClient,
		requestOptions:  cfg.requestOptions,
		observer:        cfg.observer,
	}, nil
}

func newLuaValidatorConfig(opts ...LuaValidatorOption) luaValidatorConfig {
	cfg := luaValidatorConfig{
		configSource: luaservices.NewMapConfigSource(nil),
		observer:     NoOpTrustObserver{},
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	if cfg.configSource == nil {
		cfg.configSource = luaservices.NewMapConfigSource(nil)
	}
	if cfg.httpClient == nil {
		cfg.httpClient = http.DefaultClient
	}
	if cfg.observer == nil {
		cfg.observer = NoOpTrustObserver{}
	}
	return cfg
}

// CredentialTypes implements the Validator interface.
func (v *LuaValidator) CredentialTypes() []CredentialType {
	return slices.Clone(v.credentialTypes)
}

// Validate implements the Validator interface.
func (v *LuaValidator) Validate(ctx context.Context, credential Credential) (*Result, error) {
	ctx, p := v.observer.LuaValidateStarted(ctx, v.name)
	defer p.End()

	if credential == nil {
		err := fmt.Errorf("credential cannot be nil")
		p.TokenInvalid(err)
		return nil, err
	}
	if !slices.Contains(v.credentialTypes, credential.Type()) {
		err := fmt.Errorf("credential type %s not supported", credential.Type())
		p.TokenInvalid(err)
		return nil, err
	}

	input := ValidatorInput{Credential: credential}

	L := lua.NewState()
	defer L.Close()

	var httpOpts []luaservices.HTTPServiceOption
	if v.requestOptions != nil {
		httpOpts = append(httpOpts, luaservices.WithRequestOptions(v.requestOptions))
	}
	httpService, err := luaservices.NewHTTPService(ctx, v.httpClient, httpOpts...)
	if err != nil {
		p.ScriptExecutionFailed(err)
		return nil, fmt.Errorf("failed to create http service: %w", err)
	}
	httpService.Register(L)

	configService := luaservices.NewConfigService(v.configSource)
	configService.Register(L)

	jsonService := luaservices.NewJSONService()
	jsonService.Register(L)

	if err := luaservices.LoadProto(L, v.proto); err != nil {
		p.ScriptLoadFailed(err)
		return nil, fmt.Errorf("failed to load script: %w", err)
	}

	inputTable, err := validatorInputToLuaTable(L, input)
	if err != nil {
		p.ScriptExecutionFailed(err)
		return nil, err
	}
	validateFunc := L.GetGlobal(validateFuncName)
	if err := L.CallByParam(lua.P{
		Fn:      validateFunc,
		NRet:    1,
		Protect: true,
	}, inputTable); err != nil {
		p.ScriptExecutionFailed(err)
		return nil, fmt.Errorf("script execution failed: %w", err)
	}

	ret := L.Get(-1)
	L.Pop(1)

	if ret.Type() == lua.LTNil {
		p.ValidationRejected()
		return nil, ErrInvalidToken
	}
	if ret.Type() != lua.LTTable {
		p.InvalidReturnType(ret.Type().String())
		return nil, fmt.Errorf("validate function must return a table or nil, got %s", ret.Type())
	}

	result, err := luaTableToValidationResult(ret.(*lua.LTable))
	if err != nil {
		p.ResultConversionFailed(err)
		return nil, err
	}

	p.ValidationCompleted()
	return result, nil
}

// CacheableLuaValidator is a Lua validator that implements CacheableValidator.
type CacheableLuaValidator struct {
	*LuaValidator
}

// NewCacheableLuaValidator creates a Lua validator with validate_cache_key(input).
func NewCacheableLuaValidator(name ScriptName, script string, credentialTypes []CredentialType, opts ...LuaValidatorOption) (*CacheableLuaValidator, error) {
	base, err := NewLuaValidator(name, script, credentialTypes, opts...)
	if err != nil {
		return nil, err
	}
	if err := luaservices.ValidateFunction(base.proto, validateCacheKeyFuncName); err != nil {
		return nil, err
	}

	return &CacheableLuaValidator{
		LuaValidator: base,
	}, nil
}

// CacheKey implements CacheableValidator.
func (v *CacheableLuaValidator) CacheKey(credential Credential) (ValidatorInput, error) {
	if credential == nil {
		return ValidatorInput{}, fmt.Errorf("credential cannot be nil")
	}
	if !slices.Contains(v.credentialTypes, credential.Type()) {
		return ValidatorInput{}, fmt.Errorf("credential type %s not supported", credential.Type())
	}

	input := ValidatorInput{Credential: credential}

	L := lua.NewState()
	defer L.Close()

	configService := luaservices.NewConfigService(v.configSource)
	configService.Register(L)

	jsonService := luaservices.NewJSONService()
	jsonService.Register(L)

	if err := luaservices.LoadProto(L, v.proto); err != nil {
		return ValidatorInput{}, fmt.Errorf("failed to load script: %w", err)
	}

	inputTable, err := validatorInputToLuaTable(L, input)
	if err != nil {
		return ValidatorInput{}, err
	}
	cacheKeyFunc := L.GetGlobal(validateCacheKeyFuncName)
	if err := L.CallByParam(lua.P{
		Fn:      cacheKeyFunc,
		NRet:    1,
		Protect: true,
	}, inputTable); err != nil {
		return ValidatorInput{}, fmt.Errorf("script execution failed: %w", err)
	}

	ret := L.Get(-1)
	L.Pop(1)

	if ret.Type() != lua.LTTable {
		return ValidatorInput{}, fmt.Errorf("%s function must return a table, got %s", validateCacheKeyFuncName, ret.Type())
	}

	return luaTableToValidatorInput(ret.(*lua.LTable))
}

func validatorInputToLuaTable(L *lua.LState, input ValidatorInput) (*lua.LTable, error) {
	credJSON, err := MarshalCredentialJSON(input.Credential)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential for Lua: %w", err)
	}
	var credMap map[string]any
	if err := json.Unmarshal(credJSON, &credMap); err != nil {
		return nil, fmt.Errorf("failed to unmarshal credential JSON: %w", err)
	}

	tbl := L.NewTable()
	credTbl := luaservices.GoToLua(L, credMap)
	L.SetField(tbl, "credential", credTbl)
	return tbl, nil
}

func luaTableToValidatorInput(tbl *lua.LTable) (ValidatorInput, error) {
	credLV := tbl.RawGetString("credential")
	if credLV.Type() != lua.LTTable {
		return ValidatorInput{}, fmt.Errorf("validator input must contain a credential table")
	}

	credMap := luaservices.LuaToGo(credLV)
	credJSON, err := json.Marshal(credMap)
	if err != nil {
		return ValidatorInput{}, fmt.Errorf("failed to marshal credential from Lua table: %w", err)
	}

	cred, err := UnmarshalCredentialJSON(credJSON)
	if err != nil {
		return ValidatorInput{}, err
	}
	return ValidatorInput{Credential: cred}, nil
}

func luaTableToValidationResult(tbl *lua.LTable) (*Result, error) {
	result := &Result{
		Subject:     lua.LVAsString(tbl.RawGetString("subject")),
		Issuer:      lua.LVAsString(tbl.RawGetString("issuer")),
		TrustDomain: lua.LVAsString(tbl.RawGetString("trust_domain")),
		Scope:       lua.LVAsString(tbl.RawGetString("scope")),
	}

	if result.Subject == "" {
		return nil, fmt.Errorf("subject is required")
	}

	claimsLV := tbl.RawGetString("claims")
	if claimsLV.Type() == lua.LTTable {
		result.Claims = claims.Claims(luaTableToMap(claimsLV.(*lua.LTable)))
	}

	expiresAt, err := luaValueToTime(tbl.RawGetString("expires_at"))
	if err != nil {
		return nil, fmt.Errorf("invalid expires_at: %w", err)
	}
	result.ExpiresAt = expiresAt

	issuedAt, err := luaValueToTime(tbl.RawGetString("issued_at"))
	if err != nil {
		return nil, fmt.Errorf("invalid issued_at: %w", err)
	}
	result.IssuedAt = issuedAt

	if audienceLV := tbl.RawGetString("audience"); audienceLV.Type() == lua.LTTable {
		audience, err := luaTableToStringSlice(audienceLV.(*lua.LTable))
		if err != nil {
			return nil, fmt.Errorf("invalid audience: %w", err)
		}
		result.Audience = audience
	}

	return result, nil
}

func luaValueToTime(value lua.LValue) (time.Time, error) {
	switch v := value.(type) {
	case *lua.LNilType:
		return time.Time{}, nil
	case lua.LNumber:
		return time.Unix(int64(v), 0), nil
	case lua.LString:
		if string(v) == "" {
			return time.Time{}, nil
		}
		if unix, err := strconv.ParseInt(string(v), 10, 64); err == nil {
			return time.Unix(unix, 0), nil
		}
		parsed, err := time.Parse(time.RFC3339, string(v))
		if err != nil {
			return time.Time{}, err
		}
		return parsed, nil
	default:
		return time.Time{}, fmt.Errorf("expected number, string, or nil, got %s", value.Type())
	}
}

func luaTableToStringSlice(tbl *lua.LTable) ([]string, error) {
	result := make([]string, 0, tbl.Len())
	for i := 1; i <= tbl.Len(); i++ {
		value := tbl.RawGetInt(i)
		if value.Type() != lua.LTString {
			return nil, fmt.Errorf("entry %d must be a string", i)
		}
		result = append(result, value.String())
	}
	return result, nil
}

func luaTableToMap(tbl *lua.LTable) map[string]any {
	result := make(map[string]any)
	tbl.ForEach(func(k, v lua.LValue) {
		if k.Type() == lua.LTString {
			result[k.String()] = luaservices.LuaToGo(v)
		}
	})
	return result
}
