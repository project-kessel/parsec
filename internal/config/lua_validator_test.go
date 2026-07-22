package config

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/project-kessel/parsec/internal/observer"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestNewTrustStore_LuaValidatorWithCaching(t *testing.T) {
	const luaScript = `
function validate(input)
  if input.credential.token ~= config.get("expected_token") then
    return nil
  end
  return {
    subject = "lua-user",
    issuer = "https://issuer.example.com",
    trust_domain = "lua.example.com",
    claims = {source = "lua"},
    expires_at = 4102444800
  }
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

	store, err := NewTrustStore(TrustStoreConfig{
		Type: "filtered_store",
		Validators: []NamedValidatorConfig{
			{
				Name: "lua-validator",
				ValidatorConfig: ValidatorConfig{
					Type:            "lua_validator",
					Script:          luaScript,
					CredentialTypes: []string{"bearer"},
					Config: map[string]any{
						"expected_token": "valid",
					},
					Caching: &CachingConfig{
						Type: "in_memory",
						TTL:  "10m",
					},
				},
			},
		},
	}, testHTTPRegistry(t), observer.NoOp())
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}

	result, err := store.Validate(context.Background(), &trust.BearerCredential{Token: "valid"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Subject != "lua-user" {
		t.Fatalf("Subject=%q", result.Subject)
	}
	if result.Claims.GetString("source") != "lua" {
		t.Fatalf("source=%v", result.Claims["source"])
	}
}

func TestNewTrustStore_LuaValidator_BasicAuthCredential(t *testing.T) {
	const luaScript = `
function validate(input)
  local username = input.credential.username
  local password = input.credential.password

  if username == nil or username == "" or password == nil or password == "" then
    return nil
  end

  -- Parse "org_id|username" format
  local pipe_pos = string.find(username, "|", 1, true)
  if pipe_pos == nil then
    return nil
  end

  local org_id = string.sub(username, 1, pipe_pos - 1)
  local parsed_username = string.sub(username, pipe_pos + 1)

  local claims = {}
  if org_id ~= "" then
    claims.org_id = org_id
  end

  return {
    subject = parsed_username,
    issuer = "https://registry.example.com",
    trust_domain = config.get("trust_domain"),
    claims = claims
  }
end

function validate_cache_key(input)
  return {
    credential = {
      type = input.credential.type,
      username = input.credential.username,
      password = input.credential.password
    }
  }
end
`

	store, err := NewTrustStore(TrustStoreConfig{
		Type: "stub_store",
		Validators: []NamedValidatorConfig{
			{
				Name: "registry-auth",
				ValidatorConfig: ValidatorConfig{
					Type:            "lua_validator",
					Script:          luaScript,
					CredentialTypes: []string{"basic_auth"},
					Config: map[string]any{
						"trust_domain": "registry.example.com",
					},
					Caching: &CachingConfig{
						Type: "in_memory",
						TTL:  "5m",
					},
				},
			},
		},
	}, testHTTPRegistry(t), observer.NoOp())
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}

	result, err := store.Validate(context.Background(), &trust.BasicAuthCredential{
		Username: "123|alice",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Subject != "alice" {
		t.Fatalf("Subject=%q, want alice", result.Subject)
	}
	if result.TrustDomain != "registry.example.com" {
		t.Fatalf("TrustDomain=%q", result.TrustDomain)
	}
	if result.Claims.GetString("org_id") != "123" {
		t.Fatalf("org_id=%v", result.Claims["org_id"])
	}
	// Accepted: no org_id (pipe at start)
	result, err = store.Validate(context.Background(), &trust.BasicAuthCredential{
		Username: "|alice",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("Validate no-org-id: %v", err)
	}
	if result.Subject != "alice" {
		t.Fatalf("Subject=%q, want alice", result.Subject)
	}
	if result.Claims.Has("org_id") {
		t.Fatalf("org_id should not be set, got %v", result.Claims["org_id"])
	}
	// Rejected: missing pipe separator
	_, err = store.Validate(context.Background(), &trust.BasicAuthCredential{
		Username: "no-pipe",
		Password: "secret",
	})
	if err == nil {
		t.Fatal("expected error for username without pipe separator")
	}

	// Rejected: empty credentials
	_, err = store.Validate(context.Background(), &trust.BasicAuthCredential{
		Username: "",
		Password: "",
	})
	if err == nil {
		t.Fatal("expected error for empty credentials")
	}
}

func readBOPUserResolverScript(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	scriptPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "configs", "scripts", "bop_user_resolver.lua")
	b, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("failed to read bop_user_resolver.lua: %v", err)
	}
	return string(b)
}

// validBOPUserJSON is a full BOP user response for test fixtures.
var validBOPUserJSON = mustMarshal([]map[string]any{{
	"id":             "12345",
	"org_id":         "67890",
	"account_number": "11111",
	"email":          "alice@example.com",
	"first_name":     "Alice",
	"last_name":      "Developer",
	"username":       "alice",
	"is_org_admin":   true,
	"is_internal":    false,
	"is_active":      true,
	"locale":         "en_US",
}})

func mustMarshal(v any) string {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return string(b)
}

func newBOPTestStore(t *testing.T, bopURL string) trust.Store {
	t.Helper()
	store, err := NewTrustStore(TrustStoreConfig{
		Type: "stub_store",
		Validators: []NamedValidatorConfig{
			{
				Name: "bop-user-resolver",
				ValidatorConfig: ValidatorConfig{
					Type:            "lua_validator",
					Script:          readBOPUserResolverScript(t),
					CredentialTypes: []string{"bearer"},
					Config: map[string]any{
						"bop_url":      bopURL,
						"users_path":   "/v1/users",
						"trust_domain": "bop.redhat.com",
						"api_token":    "test-token",
						"client_id":    "test-client",
						"environment":  "test",
					},
					Caching: &CachingConfig{
						Type: "in_memory",
						TTL:  "5m",
					},
				},
			},
		},
	}, testHTTPRegistry(t), observer.NoOp())
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}
	return store
}

func TestNewTrustStore_BOPUserResolver_ValidUser(t *testing.T) {
	t.Parallel()
	var receivedHeaders http.Header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		receivedHeaders = r.Header.Clone()
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validBOPUserJSON))
	}))
	defer server.Close()

	store := newBOPTestStore(t, server.URL)
	result, err := store.Validate(context.Background(), &trust.BearerCredential{Token: "alice"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if result.Subject != "12345" {
		t.Errorf("Subject=%q, want 12345", result.Subject)
	}
	if result.TrustDomain != "bop.redhat.com" {
		t.Errorf("TrustDomain=%q, want bop.redhat.com", result.TrustDomain)
	}
	if result.Issuer != server.URL {
		t.Errorf("Issuer=%q, want %s", result.Issuer, server.URL)
	}

	// Verify all 11 claims + identity_source marker
	assertClaim := func(key, want string) {
		t.Helper()
		if got := result.Claims.GetString(key); got != want {
			t.Errorf("claims[%s]=%q, want %q", key, got, want)
		}
	}
	assertClaim("org_id", "67890")
	assertClaim("account_number", "11111")
	assertClaim("email", "alice@example.com")
	assertClaim("first_name", "Alice")
	assertClaim("last_name", "Developer")
	assertClaim("username", "alice")
	assertClaim("user_id", "12345")
	assertClaim("locale", "en_US")
	assertClaim("identity_source", "bop")

	if result.Claims["is_org_admin"] != true {
		t.Errorf("is_org_admin=%v, want true", result.Claims["is_org_admin"])
	}
	if result.Claims["is_internal"] != false {
		t.Errorf("is_internal=%v, want false", result.Claims["is_internal"])
	}
	if result.Claims["is_active"] != true {
		t.Errorf("is_active=%v, want true", result.Claims["is_active"])
	}

	// Verify auth headers were sent to BOP
	if receivedHeaders.Get("X-Rh-Apitoken") != "test-token" {
		t.Errorf("x-rh-apitoken=%q, want test-token", receivedHeaders.Get("X-Rh-Apitoken"))
	}
	if receivedHeaders.Get("X-Rh-Clientid") != "test-client" {
		t.Errorf("x-rh-clientid=%q, want test-client", receivedHeaders.Get("X-Rh-Clientid"))
	}
	if receivedHeaders.Get("X-Rh-Insights-Env") != "test" {
		t.Errorf("x-rh-insights-env=%q, want test", receivedHeaders.Get("X-Rh-Insights-Env"))
	}
}

func TestNewTrustStore_BOPUserResolver_UnknownUser(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[]`))
	}))
	defer server.Close()

	store := newBOPTestStore(t, server.URL)
	_, err := store.Validate(context.Background(), &trust.BearerCredential{Token: "unknown"})
	if err == nil {
		t.Fatal("expected error for unknown user")
	}
}

func TestNewTrustStore_BOPUserResolver_Non200Status(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer server.Close()

	store := newBOPTestStore(t, server.URL)
	_, err := store.Validate(context.Background(), &trust.BearerCredential{Token: "alice"})
	if err == nil {
		t.Fatal("expected error for non-200 status")
	}
}

func TestNewTrustStore_BOPUserResolver_MalformedResponse(t *testing.T) {
	t.Parallel()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`not valid json`))
	}))
	defer server.Close()

	store := newBOPTestStore(t, server.URL)
	_, err := store.Validate(context.Background(), &trust.BearerCredential{Token: "alice"})
	if err == nil {
		t.Fatal("expected error for malformed response")
	}
}

func TestNewTrustStore_BOPUserResolver_MultipleUsers(t *testing.T) {
	t.Parallel()
	body := mustMarshal([]map[string]any{
		{"id": "12345", "org_id": "67890", "username": "alice"},
		{"id": "99999", "org_id": "67890", "username": "bob"},
	})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	store := newBOPTestStore(t, server.URL)
	_, err := store.Validate(context.Background(), &trust.BearerCredential{Token: "alice"})
	if err == nil {
		t.Fatal("expected error when BOP returns multiple users")
	}
}

func TestNewTrustStore_BOPUserResolver_MissingOrgID(t *testing.T) {
	t.Parallel()
	body := mustMarshal([]map[string]any{{
		"id":       "12345",
		"username": "alice",
	}})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	store := newBOPTestStore(t, server.URL)
	_, err := store.Validate(context.Background(), &trust.BearerCredential{Token: "alice"})
	if err == nil {
		t.Fatal("expected error for user missing org_id")
	}
}

func TestNewTrustStore_BOPUserResolver_MissingID(t *testing.T) {
	t.Parallel()
	body := mustMarshal([]map[string]any{{
		"org_id":   "67890",
		"username": "alice",
	}})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	store := newBOPTestStore(t, server.URL)
	_, err := store.Validate(context.Background(), &trust.BearerCredential{Token: "alice"})
	if err == nil {
		t.Fatal("expected error for user missing id")
	}
}

func TestNewTrustStore_BOPUserResolver_EmptyToken(t *testing.T) {
	t.Parallel()
	var called atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called.Store(true)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	store := newBOPTestStore(t, server.URL)
	_, err := store.Validate(context.Background(), &trust.BearerCredential{Token: ""})
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if called.Load() {
		t.Fatal("BOP should not be called for empty token")
	}
}

func TestNewTrustStore_BOPUserResolver_CacheKey(t *testing.T) {
	t.Parallel()
	var callCount atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		callCount.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validBOPUserJSON))
	}))
	defer server.Close()

	store := newBOPTestStore(t, server.URL)

	// First call hits BOP
	_, err := store.Validate(context.Background(), &trust.BearerCredential{Token: "alice"})
	if err != nil {
		t.Fatalf("first Validate: %v", err)
	}
	if got := callCount.Load(); got != 1 {
		t.Fatalf("callCount=%d, want 1 after first call", got)
	}

	// Second call with same token should be cached
	_, err = store.Validate(context.Background(), &trust.BearerCredential{Token: "alice"})
	if err != nil {
		t.Fatalf("second Validate: %v", err)
	}
	if got := callCount.Load(); got != 1 {
		t.Fatalf("callCount=%d, want 1 after cached call", got)
	}
}

func TestNewTrustStore_LuaValidator_InvalidCachingType(t *testing.T) {
	t.Parallel()

	const luaScript = `
function validate(input)
  return {
    subject = "user",
    issuer = "https://issuer.example.com",
    trust_domain = "example.com",
  }
end
`
	_, err := NewTrustStore(TrustStoreConfig{
		Type: "stub_store",
		Validators: []NamedValidatorConfig{
			{
				Name: "lua-validator",
				ValidatorConfig: ValidatorConfig{
					Type:            "lua_validator",
					Script:          luaScript,
					CredentialTypes: []string{"bearer"},
					Caching: &CachingConfig{
						Type: "redis",
					},
				},
			},
		},
	}, testHTTPRegistry(t), observer.NoOp())

	if err == nil {
		t.Fatal("expected error for invalid caching type, got nil")
	}
	if !strings.Contains(err.Error(), "unknown validator caching type") {
		t.Fatalf("expected 'unknown validator caching type' error, got: %v", err)
	}
}
