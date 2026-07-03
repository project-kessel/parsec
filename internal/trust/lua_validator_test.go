package trust

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/clock"
	luaservices "github.com/project-kessel/parsec/internal/lua"
)

func TestNewLuaValidator(t *testing.T) {
	tests := []struct {
		name    string
		ctor    func() (*LuaValidator, error)
		wantErr string
	}{
		{
			name: "valid",
			ctor: func() (*LuaValidator, error) {
				return NewLuaValidator("test", `function validate(input) return nil end`, []CredentialType{CredentialTypeBearer})
			},
		},
		{
			name: "missing name",
			ctor: func() (*LuaValidator, error) {
				return NewLuaValidator("", `function validate(input) return nil end`, []CredentialType{CredentialTypeBearer})
			},
			wantErr: "validator name is required",
		},
		{
			name: "missing script",
			ctor: func() (*LuaValidator, error) {
				return NewLuaValidator("test", "", []CredentialType{CredentialTypeBearer})
			},
			wantErr: "script is required",
		},
		{
			name: "missing credential types",
			ctor: func() (*LuaValidator, error) {
				return NewLuaValidator("test", `function validate(input) return nil end`, nil)
			},
			wantErr: "at least one credential type is required",
		},
		{
			name: "missing validate function",
			ctor: func() (*LuaValidator, error) {
				return NewLuaValidator("test", `function other(input) return nil end`, []CredentialType{CredentialTypeBearer})
			},
			wantErr: "script must define a 'validate' function",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			validator, err := tt.ctor()
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err=%v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if validator == nil {
				t.Fatal("expected validator")
			}
		})
	}
}

func TestLuaValidator_Validate(t *testing.T) {
	const script = `
function validate(input)
  if input.credential.type ~= "bearer" then
    error("unexpected credential type")
  end
  if input.credential.token ~= "valid-token" then
    return nil
  end
  return {
    subject = "user@example.com",
    issuer = "https://issuer.example.com",
    trust_domain = "example.com",
    claims = {
      email = "user@example.com",
      groups = {"admin", "user"}
    },
    expires_at = 4102444800,
    issued_at = "2024-01-01T00:00:00Z",
    audience = {"parsec"},
    scope = "read write"
  }
end
`

	validator, err := NewLuaValidator("test", script, []CredentialType{CredentialTypeBearer})
	if err != nil {
		t.Fatalf("NewLuaValidator: %v", err)
	}

	result, err := validator.Validate(context.Background(), &BearerCredential{Token: "valid-token"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Subject != "user@example.com" {
		t.Fatalf("Subject=%q, want user@example.com", result.Subject)
	}
	if result.Issuer != "https://issuer.example.com" {
		t.Fatalf("Issuer=%q", result.Issuer)
	}
	if result.TrustDomain != "example.com" {
		t.Fatalf("TrustDomain=%q", result.TrustDomain)
	}
	if result.Claims.GetString("email") != "user@example.com" {
		t.Fatalf("email claim=%v", result.Claims["email"])
	}
	if len(result.Audience) != 1 || result.Audience[0] != "parsec" {
		t.Fatalf("Audience=%v", result.Audience)
	}
	if result.Scope != "read write" {
		t.Fatalf("Scope=%q", result.Scope)
	}

	_, err = validator.Validate(context.Background(), &BearerCredential{Token: "bad-token"})
	if !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("err=%v, want ErrInvalidToken", err)
	}
}

func TestLuaValidator_HTTPConfigAndJSONServices(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-API-Key") != "secret" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		_, _ = w.Write([]byte(`{"active":true,"sub":"http-user","email":"http@example.com"}`))
	}))
	defer server.Close()

	script := `
function validate(input)
  local body = json.encode({token = input.credential.token})
  local resp = http.post(config.get("introspection_url"), body, {["Content-Type"] = "application/json"})
  if resp.status ~= 200 then
    return nil
  end
  local decoded = json.decode(resp.body)
  if not decoded.active then
    return nil
  end
  return {
    subject = decoded.sub,
    issuer = config.get("issuer"),
    trust_domain = config.get("trust_domain"),
    claims = {email = decoded.email},
    expires_at = 4102444800
  }
end
`

	validator, err := NewLuaValidator("http", script, []CredentialType{CredentialTypeBearer},
		WithLuaConfigSource(luaservices.NewMapConfigSource(map[string]any{
			"introspection_url": server.URL,
			"issuer":            "https://issuer.example.com",
			"trust_domain":      "example.com",
		})),
		WithLuaRequestOptions(func(req *http.Request) error {
			req.Header.Set("X-API-Key", "secret")
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("NewLuaValidator: %v", err)
	}

	result, err := validator.Validate(context.Background(), &BearerCredential{Token: "valid"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Subject != "http-user" {
		t.Fatalf("Subject=%q", result.Subject)
	}
	if result.Claims.GetString("email") != "http@example.com" {
		t.Fatalf("email=%v", result.Claims["email"])
	}
}

func TestCacheableLuaValidator_CacheKey(t *testing.T) {
	const script = `
function validate(input)
  return {subject = "user", expires_at = 4102444800}
end

function validate_cache_key(input)
  return {
    credential = {
      type = input.credential.type,
      token = input.credential.token
    }
  }
end
`

	validator, err := NewCacheableLuaValidator("test", script, []CredentialType{CredentialTypeBearer})
	if err != nil {
		t.Fatalf("NewCacheableLuaValidator: %v", err)
	}

	key, err := validator.CacheKey(&BearerCredential{Token: "abc"})
	if err != nil {
		t.Fatalf("CacheKey: %v", err)
	}
	bearer, ok := key.Credential.(*BearerCredential)
	if !ok {
		t.Fatalf("expected *BearerCredential, got %T", key.Credential)
	}
	if bearer.Token != "abc" {
		t.Fatalf("Token=%q, want abc", bearer.Token)
	}
}

func TestCacheableLuaValidator_CacheKey_NilCredential(t *testing.T) {
	const script = `
function validate(input)
  return {subject = "user", expires_at = 4102444800}
end

function validate_cache_key(input)
  return {
    credential = {
      type = input.credential.type,
      token = input.credential.token
    }
  }
end
`
	validator, err := NewCacheableLuaValidator("test", script, []CredentialType{CredentialTypeBearer})
	if err != nil {
		t.Fatalf("NewCacheableLuaValidator: %v", err)
	}

	_, err = validator.CacheKey(nil)
	if err == nil {
		t.Fatal("expected error for nil credential")
	}
	if !strings.Contains(err.Error(), "credential cannot be nil") {
		t.Fatalf("err=%v, want containing 'credential cannot be nil'", err)
	}
}

func TestCacheableLuaValidator_CacheKey_UnsupportedCredentialType(t *testing.T) {
	const script = `
function validate(input)
  return {subject = "user", expires_at = 4102444800}
end

function validate_cache_key(input)
  return {
    credential = {
      type = input.credential.type,
      token = input.credential.token
    }
  }
end
`
	validator, err := NewCacheableLuaValidator("test", script, []CredentialType{CredentialTypeJWT})
	if err != nil {
		t.Fatalf("NewCacheableLuaValidator: %v", err)
	}

	_, err = validator.CacheKey(&BearerCredential{Token: "tok"})
	if err == nil {
		t.Fatal("expected error for unsupported credential type")
	}
	if !strings.Contains(err.Error(), "not supported") {
		t.Fatalf("err=%q, want containing 'not supported'", err)
	}
}

func TestLuaValidator_Validate_NilCredential(t *testing.T) {
	const script = `
function validate(input)
  return {subject = "user", expires_at = 4102444800}
end
`
	validator, err := NewLuaValidator("test", script, []CredentialType{CredentialTypeBearer})
	if err != nil {
		t.Fatalf("NewLuaValidator: %v", err)
	}

	_, err = validator.Validate(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil credential")
	}
	if !strings.Contains(err.Error(), "credential cannot be nil") {
		t.Fatalf("err=%v, want containing 'credential cannot be nil'", err)
	}
}

func TestNewLuaValidator_CompileError(t *testing.T) {
	_, err := NewLuaValidator("test", `function validate(`, []CredentialType{CredentialTypeBearer})
	if err == nil {
		t.Fatal("expected error for invalid syntax")
	}
	if !strings.Contains(err.Error(), "failed to parse script") {
		t.Fatalf("err=%q, want containing 'failed to parse script'", err)
	}
}

func TestLuaValidator_Validate_UnsupportedCredentialType(t *testing.T) {
	const script = `
function validate(input)
  return {subject = "user"}
end
`
	validator, err := NewLuaValidator("test", script, []CredentialType{CredentialTypeJWT})
	if err != nil {
		t.Fatalf("NewLuaValidator: %v", err)
	}

	_, err = validator.Validate(context.Background(), &BearerCredential{Token: "tok"})
	if err == nil {
		t.Fatal("expected error for unsupported credential type")
	}
	if !strings.Contains(err.Error(), "credential type bearer not supported") {
		t.Fatalf("err=%q, want containing 'not supported'", err)
	}
}

func TestLuaValidator_Validate_InvalidReturnType(t *testing.T) {
	const script = `
function validate(input)
  return "not a table"
end
`
	validator, err := NewLuaValidator("test", script, []CredentialType{CredentialTypeBearer})
	if err != nil {
		t.Fatalf("NewLuaValidator: %v", err)
	}

	_, err = validator.Validate(context.Background(), &BearerCredential{Token: "tok"})
	if err == nil {
		t.Fatal("expected error for non-table return")
	}
	if !strings.Contains(err.Error(), "validate function must return a table or nil") {
		t.Fatalf("err=%q, want containing 'must return a table or nil'", err)
	}
}

func TestLuaValidator_Validate_ScriptExecutionError(t *testing.T) {
	const script = `
function validate(input)
  error("something went wrong")
end
`
	validator, err := NewLuaValidator("test", script, []CredentialType{CredentialTypeBearer})
	if err != nil {
		t.Fatalf("NewLuaValidator: %v", err)
	}

	_, err = validator.Validate(context.Background(), &BearerCredential{Token: "tok"})
	if err == nil {
		t.Fatal("expected error from script execution")
	}
	if !strings.Contains(err.Error(), "script execution failed") {
		t.Fatalf("err=%q, want containing 'script execution failed'", err)
	}
}

func TestLuaValidator_Validate_MissingSubject(t *testing.T) {
	const script = `
function validate(input)
  return {issuer = "test-issuer"}
end
`
	validator, err := NewLuaValidator("test", script, []CredentialType{CredentialTypeBearer})
	if err != nil {
		t.Fatalf("NewLuaValidator: %v", err)
	}

	_, err = validator.Validate(context.Background(), &BearerCredential{Token: "tok"})
	if err == nil {
		t.Fatal("expected error for missing subject")
	}
	if !strings.Contains(err.Error(), "subject is required") {
		t.Fatalf("err=%q, want containing 'subject is required'", err)
	}
}

func TestLuaValidator_Validate_ExpiresAtFormats(t *testing.T) {
	tests := []struct {
		name      string
		expiresAt string
		wantErr   string
		wantUnix  int64
	}{
		{
			name:      "numeric string",
			expiresAt: `"1704067200"`,
			wantUnix:  1704067200,
		},
		{
			name:      "invalid string",
			expiresAt: `"not-a-time"`,
			wantErr:   "invalid expires_at",
		},
		{
			name:      "empty string",
			expiresAt: `""`,
			wantUnix:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := `
function validate(input)
  return {subject = "user", expires_at = ` + tt.expiresAt + `}
end
`
			validator, err := NewLuaValidator("test", script, []CredentialType{CredentialTypeBearer})
			if err != nil {
				t.Fatalf("NewLuaValidator: %v", err)
			}

			result, err := validator.Validate(context.Background(), &BearerCredential{Token: "tok"})
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("err=%v, want containing %q", err, tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.wantUnix == 0 {
				if !result.ExpiresAt.IsZero() {
					t.Fatalf("ExpiresAt=%v, want zero", result.ExpiresAt)
				}
			} else if result.ExpiresAt.Unix() != tt.wantUnix {
				t.Fatalf("ExpiresAt.Unix()=%d, want %d", result.ExpiresAt.Unix(), tt.wantUnix)
			}
		})
	}
}

func TestLuaValidator_Validate_ExpiresAtUnsupportedType(t *testing.T) {
	const script = `
function validate(input)
  return {subject = "user", expires_at = true}
end
`
	validator, err := NewLuaValidator("test", script, []CredentialType{CredentialTypeBearer})
	if err != nil {
		t.Fatalf("NewLuaValidator: %v", err)
	}

	_, err = validator.Validate(context.Background(), &BearerCredential{Token: "tok"})
	if err == nil {
		t.Fatal("expected error for boolean expires_at")
	}
	if !strings.Contains(err.Error(), "invalid expires_at") {
		t.Fatalf("err=%q, want containing 'invalid expires_at'", err)
	}
}

func TestLuaValidator_Validate_AudienceNonStringEntry(t *testing.T) {
	const script = `
function validate(input)
  return {subject = "user", audience = {"valid", 42}}
end
`
	validator, err := NewLuaValidator("test", script, []CredentialType{CredentialTypeBearer})
	if err != nil {
		t.Fatalf("NewLuaValidator: %v", err)
	}

	_, err = validator.Validate(context.Background(), &BearerCredential{Token: "tok"})
	if err == nil {
		t.Fatal("expected error for non-string audience entry")
	}
	if !strings.Contains(err.Error(), "invalid audience") {
		t.Fatalf("err=%q, want containing 'invalid audience'", err)
	}
}

func TestLuaValidator_CredentialTypes(t *testing.T) {
	types := []CredentialType{CredentialTypeBearer, CredentialTypeJWT}
	validator, err := NewLuaValidator("test", `function validate(input) return nil end`, types)
	if err != nil {
		t.Fatalf("NewLuaValidator: %v", err)
	}

	got := validator.CredentialTypes()
	if len(got) != 2 || got[0] != CredentialTypeBearer || got[1] != CredentialTypeJWT {
		t.Fatalf("CredentialTypes=%v, want [bearer jwt]", got)
	}

	// Mutating the returned slice should not affect the validator.
	got[0] = "mutated"
	fresh := validator.CredentialTypes()
	if fresh[0] != CredentialTypeBearer {
		t.Fatal("CredentialTypes returned a non-cloned slice")
	}
}

func TestNewCacheableLuaValidator_RequiresValidateCacheKey(t *testing.T) {
	_, err := NewCacheableLuaValidator("test", `function validate(input) return nil end`, []CredentialType{CredentialTypeBearer})
	if err == nil || !strings.Contains(err.Error(), "script must define a 'validate_cache_key' function") {
		t.Fatalf("err=%v, want validate_cache_key error", err)
	}
}

func TestCacheableLuaValidator_CacheKey_ScriptError(t *testing.T) {
	const script = `
function validate(input) return {subject = "user"} end
function validate_cache_key(input)
  error("cache key failed")
end
`
	validator, err := NewCacheableLuaValidator("test", script, []CredentialType{CredentialTypeBearer})
	if err != nil {
		t.Fatalf("NewCacheableLuaValidator: %v", err)
	}

	_, err = validator.CacheKey(&BearerCredential{Token: "tok"})
	if err == nil {
		t.Fatal("expected error from cache key script")
	}
	if !strings.Contains(err.Error(), "script execution failed") {
		t.Fatalf("err=%q, want containing 'script execution failed'", err)
	}
}

func TestCacheableLuaValidator_CacheKey_NonTableReturn(t *testing.T) {
	const script = `
function validate(input) return {subject = "user"} end
function validate_cache_key(input)
  return "not a table"
end
`
	validator, err := NewCacheableLuaValidator("test", script, []CredentialType{CredentialTypeBearer})
	if err != nil {
		t.Fatalf("NewCacheableLuaValidator: %v", err)
	}

	_, err = validator.CacheKey(&BearerCredential{Token: "tok"})
	if err == nil {
		t.Fatal("expected error for non-table return from cache key")
	}
	if !strings.Contains(err.Error(), "must return a table") {
		t.Fatalf("err=%q, want containing 'must return a table'", err)
	}
}

func TestNewLuaValidatorConfig_NilOverrides(t *testing.T) {
	// Passing nil configSource and observer via options should fall back to defaults.
	validator, err := NewLuaValidator("test", `function validate(input) return nil end`,
		[]CredentialType{CredentialTypeBearer},
		WithLuaConfigSource(nil),
		WithLuaValidatorObserver(nil),
	)
	if err != nil {
		t.Fatalf("NewLuaValidator: %v", err)
	}
	if validator.configSource == nil {
		t.Fatal("expected non-nil configSource after nil override")
	}
	if validator.observer == nil {
		t.Fatal("expected non-nil observer after nil override")
	}
}

type countingCacheableValidator struct {
	count     int
	expiresAt time.Time
}

func (v *countingCacheableValidator) CredentialTypes() []CredentialType {
	return []CredentialType{CredentialTypeBearer}
}

func (v *countingCacheableValidator) Validate(_ context.Context, credential Credential) (*Result, error) {
	v.count++
	bearer, ok := credential.(*BearerCredential)
	if !ok {
		return nil, ErrInvalidToken
	}
	return &Result{
		Subject:   bearer.Token,
		ExpiresAt: v.expiresAt,
	}, nil
}

func (v *countingCacheableValidator) CacheKey(credential Credential) (ValidatorInput, error) {
	return ValidatorInput{Credential: credential}, nil
}

// recordingInMemoryValidateProbe captures which cache-outcome method was called.
type recordingInMemoryValidateProbe struct {
	NoOpInMemoryValidateProbe
	hitCalled     bool
	missCalled    bool
	expiredCalled bool
}

func (p *recordingInMemoryValidateProbe) CacheHit()     { p.hitCalled = true }
func (p *recordingInMemoryValidateProbe) CacheMiss()    { p.missCalled = true }
func (p *recordingInMemoryValidateProbe) CacheExpired() { p.expiredCalled = true }

// recordingInMemoryValidateObserver collects a probe per Validate call.
type recordingInMemoryValidateObserver struct {
	NoOpTrustObserver
	probes []*recordingInMemoryValidateProbe
}

func (o *recordingInMemoryValidateObserver) InMemoryValidateStarted(ctx context.Context, _ string) (context.Context, InMemoryValidateProbe) {
	p := &recordingInMemoryValidateProbe{}
	o.probes = append(o.probes, p)
	return ctx, p
}

func TestInMemoryCachingValidator(t *testing.T) {
	clk := clock.NewFixtureClock(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	source := &countingCacheableValidator{
		expiresAt: clk.Now().Add(time.Hour),
	}
	cached := NewInMemoryCachingValidator("test", source, NoOpTrustObserver{},
		WithValidatorCacheClock(clk),
		WithValidatorCacheTTL(time.Minute),
	)

	cred := &BearerCredential{Token: "abc"}
	result, err := cached.Validate(context.Background(), cred)
	if err != nil {
		t.Fatalf("first Validate: %v", err)
	}
	if result.Subject != "abc" {
		t.Fatalf("Subject=%q", result.Subject)
	}
	if source.count != 1 {
		t.Fatalf("count=%d, want 1", source.count)
	}

	_, err = cached.Validate(context.Background(), cred)
	if err != nil {
		t.Fatalf("second Validate: %v", err)
	}
	if source.count != 1 {
		t.Fatalf("count=%d, want cached count 1", source.count)
	}

	clk.Advance(2 * time.Minute)
	_, err = cached.Validate(context.Background(), cred)
	if err != nil {
		t.Fatalf("third Validate: %v", err)
	}
	if source.count != 2 {
		t.Fatalf("count=%d, want 2 after expiry", source.count)
	}
}

func TestInMemoryCachingValidator_CacheOutcomesAreMutuallyExclusive(t *testing.T) {
	clk := clock.NewFixtureClock(time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC))
	source := &countingCacheableValidator{
		expiresAt: clk.Now().Add(time.Hour),
	}
	obs := &recordingInMemoryValidateObserver{}
	cached := NewInMemoryCachingValidator("test", source, obs,
		WithValidatorCacheClock(clk),
		WithValidatorCacheTTL(time.Minute),
	)
	cred := &BearerCredential{Token: "abc"}

	// Call 0: cold miss — entry not in cache.
	if _, err := cached.Validate(context.Background(), cred); err != nil {
		t.Fatalf("cold miss: %v", err)
	}
	p := obs.probes[0]
	if !p.missCalled {
		t.Fatal("cold miss: expected CacheMiss")
	}
	if p.hitCalled || p.expiredCalled {
		t.Fatalf("cold miss: unexpected hit=%v expired=%v", p.hitCalled, p.expiredCalled)
	}

	// Call 1: cache hit.
	if _, err := cached.Validate(context.Background(), cred); err != nil {
		t.Fatalf("cache hit: %v", err)
	}
	p = obs.probes[1]
	if !p.hitCalled {
		t.Fatal("cache hit: expected CacheHit")
	}
	if p.missCalled || p.expiredCalled {
		t.Fatalf("cache hit: unexpected miss=%v expired=%v", p.missCalled, p.expiredCalled)
	}

	// Call 2: expired — entry found but stale. CacheExpired only, not CacheMiss.
	clk.Advance(2 * time.Minute)
	if _, err := cached.Validate(context.Background(), cred); err != nil {
		t.Fatalf("expired: %v", err)
	}
	p = obs.probes[2]
	if !p.expiredCalled {
		t.Fatal("expired: expected CacheExpired")
	}
	if p.missCalled {
		t.Fatal("expired: CacheMiss must not be called when CacheExpired was called")
	}
	if p.hitCalled {
		t.Fatalf("expired: unexpected CacheHit")
	}
}

func TestDistributedCachingValidator(t *testing.T) {
	source := &countingCacheableValidator{
		expiresAt: time.Now().Add(time.Hour),
	}
	cached := NewDistributedCachingValidator("test-distributed", source, NoOpTrustObserver{}, DistributedValidatorCachingConfig{
		GroupName:      "test-validator-distributed-cache",
		CacheSizeBytes: 1 << 20,
		CacheTTL:       time.Hour,
	})

	cred := &BearerCredential{Token: "abc"}
	_, err := cached.Validate(context.Background(), cred)
	if err != nil {
		t.Fatalf("first Validate: %v", err)
	}
	_, err = cached.Validate(context.Background(), cred)
	if err != nil {
		t.Fatalf("second Validate: %v", err)
	}
	if source.count != 1 {
		t.Fatalf("count=%d, want 1", source.count)
	}
}
