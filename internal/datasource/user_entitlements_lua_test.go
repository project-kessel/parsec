package datasource

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/httpfixture"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func loadUserEntitlementsScript(t *testing.T) string {
	t.Helper()
	path := filepath.Join("..", "..", "configs", "scripts", "user_entitlements.lua")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read user_entitlements.lua: %v", err)
	}
	return string(b)
}

func consoleSubjectInput() *service.DataSourceInput {
	return &service.DataSourceInput{
		Subject: &trust.Result{
			Subject: "alice",
			Claims: map[string]any{
				"preferred_username": "alice",
				"user_id":            "user-1",
				"organization": map[string]any{
					"id":             "org-1",
					"account_number": "12345",
				},
			},
		},
	}
}

func TestUserEntitlementsLua_Success(t *testing.T) {
	const apiURL = "https://entitlements.example.internal/api/entitlements/v1/services"

	var gotIdentityHeader string
	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		if req.Method != http.MethodGet || req.URL.String() != apiURL {
			return nil
		}
		gotIdentityHeader = req.Header.Get("x-rh-identity")
		if req.Header.Get("Authorization") != "" {
			t.Error("expected no Authorization header")
		}
		return &httpfixture.Fixture{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       `{"insights":{"is_entitled":true},"openshift":{"is_entitled":false}}`,
		}
	})

	ds, err := NewCacheableLuaDataSource(CacheableLuaDataSourceConfig{
		Name:   "user_entitlements",
		Script: loadUserEntitlementsScript(t),
		ConfigSource: luaservices.NewMapConfigSource(map[string]any{
			"entitlements_api": apiURL,
		}),
		HTTPClient: &http.Client{
			Timeout: 5 * time.Second,
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: provider,
				Strict:   true,
			}),
		},
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}

	result, err := ds.Fetch(context.Background(), consoleSubjectInput())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result == nil {
		t.Fatal("expected non-nil result")
	}

	var entitlements map[string]any
	if err := json.Unmarshal(result.Data, &entitlements); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	insights, ok := entitlements["insights"].(map[string]any)
	if !ok || insights["is_entitled"] != true {
		t.Fatalf("unexpected entitlements: %v", entitlements)
	}

	if gotIdentityHeader == "" {
		t.Fatal("expected x-rh-identity header on entitlements request")
	}
	decoded, err := base64.StdEncoding.DecodeString(gotIdentityHeader)
	if err != nil {
		t.Fatalf("decode x-rh-identity: %v", err)
	}
	var envelope map[string]any
	if err := json.Unmarshal(decoded, &envelope); err != nil {
		t.Fatalf("parse identity envelope: %v", err)
	}
	identity, ok := envelope["identity"].(map[string]any)
	if !ok {
		t.Fatalf("expected identity in outbound envelope, got %v", envelope)
	}
	if identity["account_number"] != "12345" || identity["org_id"] != "org-1" {
		t.Errorf("identity account/org = %v/%v, want 12345/org-1", identity["account_number"], identity["org_id"])
	}
	if _, hasEnt := envelope["entitlements"]; hasEnt {
		t.Error("outbound identity for entitlements API should not include entitlements field")
	}
}

func TestUserEntitlementsLua_FailClosed(t *testing.T) {
	const apiURL = "https://entitlements.example.internal/api/entitlements/v1/services"
	script := loadUserEntitlementsScript(t)

	cases := []struct {
		name     string
		provider httpfixture.FixtureProvider
		wantErr  string
	}{
		{
			name: "non-200",
			provider: httpfixture.NewMapProvider(map[string]*httpfixture.Fixture{
				"GET " + apiURL: {StatusCode: 500, Body: `{"error":"boom"}`},
			}),
			wantErr: "status 500",
		},
		{
			name: "malformed JSON",
			provider: httpfixture.NewMapProvider(map[string]*httpfixture.Fixture{
				"GET " + apiURL: {StatusCode: 200, Body: `{not-json`},
			}),
			wantErr: "not valid JSON",
		},
		{
			name: "transport miss (strict fixture)",
			provider: httpfixture.NewMapProvider(map[string]*httpfixture.Fixture{
				"GET https://other.example/": {StatusCode: 200, Body: `{}`},
			}),
			wantErr: "failed",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ds, err := NewLuaDataSource(LuaDataSourceConfig{
				Name:   "user_entitlements",
				Script: script,
				ConfigSource: luaservices.NewMapConfigSource(map[string]any{
					"entitlements_api": apiURL,
				}),
				HTTPClient: &http.Client{
					Timeout: 5 * time.Second,
					Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
						Provider: tc.provider,
						Strict:   true,
					}),
				},
			})
			if err != nil {
				t.Fatalf("NewLuaDataSource: %v", err)
			}
			_, err = ds.Fetch(context.Background(), consoleSubjectInput())
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q, want substring %q", err.Error(), tc.wantErr)
			}
		})
	}
}

func newCacheOnlyDS(t *testing.T) *CacheableLuaDataSource {
	t.Helper()
	ds, err := NewCacheableLuaDataSource(CacheableLuaDataSourceConfig{
		Name:         "user_entitlements",
		Script:       loadUserEntitlementsScript(t),
		ConfigSource: luaservices.NewMapConfigSource(map[string]any{"entitlements_api": "https://entitlements.example.internal/api/entitlements/v1/services"}),
		HTTPClient:   http.DefaultClient,
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}
	return ds
}

func TestUserEntitlementsLua_CacheKey(t *testing.T) {
	ds := newCacheOnlyDS(t)

	masked := ds.CacheKey(consoleSubjectInput())
	if masked.Subject == nil || masked.Subject.Claims == nil {
		t.Fatalf("expected masked subject claims, got %+v", masked)
	}
	if masked.Subject.Claims["account_number"] != "12345" {
		t.Errorf("account_number = %v", masked.Subject.Claims["account_number"])
	}
	if masked.Subject.Claims["org_id"] != "org-1" {
		t.Errorf("org_id = %v", masked.Subject.Claims["org_id"])
	}
	if masked.Subject.Claims["user_id"] != "user-1" {
		t.Errorf("user_id = %v", masked.Subject.Claims["user_id"])
	}
	if masked.Subject.Claims["preferred_username"] != "alice" {
		t.Errorf("preferred_username = %v", masked.Subject.Claims["preferred_username"])
	}
	if masked.Subject.Subject != "" {
		t.Errorf("cache key should not include subject id, got %q", masked.Subject.Subject)
	}
}

// TestUserEntitlementsLua_CacheKey_UsernameDistinguishes is the regression test
// for the case where two users share the same account and org but have different
// usernames and no user_id — they must not share a cache entry.
func TestUserEntitlementsLua_CacheKey_UsernameDistinguishes(t *testing.T) {
	ds := newCacheOnlyDS(t)

	makeInput := func(username string) *service.DataSourceInput {
		return &service.DataSourceInput{
			Subject: &trust.Result{
				Claims: map[string]any{
					"preferred_username": username,
					"organization": map[string]any{
						"id":             "org-1",
						"account_number": "12345",
					},
				},
			},
		}
	}

	keyAlice := ds.CacheKey(makeInput("alice"))
	keyBob := ds.CacheKey(makeInput("bob"))

	if keyAlice.Subject == nil || keyBob.Subject == nil {
		t.Fatal("expected non-nil subject in cache keys")
	}
	if keyAlice.Subject.Claims["preferred_username"] == keyBob.Subject.Claims["preferred_username"] {
		t.Error("expected different preferred_username in cache keys for alice and bob")
	}
	// user_id must be empty when the claim is absent.
	if keyAlice.Subject.Claims["user_id"] != "" {
		t.Errorf("expected empty user_id when claim absent, got %q", keyAlice.Subject.Claims["user_id"])
	}
	// Shared fields are identical.
	if keyAlice.Subject.Claims["account_number"] != "12345" {
		t.Errorf("account_number = %v", keyAlice.Subject.Claims["account_number"])
	}
	if keyAlice.Subject.Claims["org_id"] != "org-1" {
		t.Errorf("org_id = %v", keyAlice.Subject.Claims["org_id"])
	}
}

// TestUserEntitlementsLua_CacheKey_FieldIndependence verifies that varying each
// identity field independently produces a different cache key, so no two distinct
// identities can share a cache entry.
func TestUserEntitlementsLua_CacheKey_FieldIndependence(t *testing.T) {
	ds := newCacheOnlyDS(t)

	base := func() map[string]any {
		return map[string]any{
			"preferred_username": "alice",
			"user_id":            "uid-1",
			"organization": map[string]any{
				"id":             "org-1",
				"account_number": "acct-1",
			},
		}
	}

	withClaims := func(claims map[string]any) *service.DataSourceInput {
		return &service.DataSourceInput{Subject: &trust.Result{Claims: claims}}
	}

	cacheKey := func(claims map[string]any) map[string]any {
		k := ds.CacheKey(withClaims(claims))
		if k.Subject == nil {
			return nil
		}
		return k.Subject.Claims
	}

	baseKey := cacheKey(base())

	cases := []struct {
		name   string
		mutate func(map[string]any)
		field  string
	}{
		{"different account_number", func(c map[string]any) { c["organization"].(map[string]any)["account_number"] = "acct-2" }, "account_number"},
		{"different org_id", func(c map[string]any) { c["organization"].(map[string]any)["id"] = "org-2" }, "org_id"},
		{"different user_id", func(c map[string]any) { c["user_id"] = "uid-2" }, "user_id"},
		{"different preferred_username", func(c map[string]any) { c["preferred_username"] = "bob" }, "preferred_username"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			claims := base()
			tc.mutate(claims)
			k := cacheKey(claims)
			if k[tc.field] == baseKey[tc.field] {
				t.Errorf("expected %s to differ from base key after mutation, but both = %v", tc.field, baseKey[tc.field])
			}
		})
	}
}

// TestUserEntitlementsLua_CacheKey_MissingClaims verifies that when all identity
// fields are absent (empty input), fetch_cache_key returns nil and the caching
// layer falls back to the full input as the key. The fallback key must not be
// the blank-fields masked structure (which would collapse all anonymous requests).
func TestUserEntitlementsLua_CacheKey_MissingClaims(t *testing.T) {
	ds := newCacheOnlyDS(t)

	empty := &service.DataSourceInput{
		Subject: &trust.Result{Claims: map[string]any{}},
	}

	k := ds.CacheKey(empty)
	// Go falls back to *input when Lua returns nil — Subject must be non-nil.
	if k.Subject == nil {
		t.Fatal("expected non-nil Subject in fallback cache key")
	}
	// The fallback key is the original input; identity keys must NOT be present
	// (no blank-fields structure that would cause anonymous requests to collide).
	if k.Subject.Claims != nil {
		for _, field := range []string{"account_number", "org_id", "user_id", "preferred_username"} {
			if _, present := k.Subject.Claims[field]; present {
				t.Errorf("unexpected identity key %q in fallback cache key; blank-fields structure must not appear", field)
			}
		}
	}
}

// TestUserEntitlementsLua_Fetch_EmptyIdentityFails verifies that fetch is rejected
// fail-closed when neither organisation nor user identity material is present,
// rather than issuing an HTTP request with a blank identity envelope.
func TestUserEntitlementsLua_Fetch_EmptyIdentityFails(t *testing.T) {
	const apiURL = "https://entitlements.example.internal/api/entitlements/v1/services"

	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:   "user_entitlements",
		Script: loadUserEntitlementsScript(t),
		ConfigSource: luaservices.NewMapConfigSource(map[string]any{
			"entitlements_api": apiURL,
		}),
		HTTPClient: http.DefaultClient,
	})
	if err != nil {
		t.Fatalf("NewLuaDataSource: %v", err)
	}

	empty := &service.DataSourceInput{
		Subject: &trust.Result{Claims: map[string]any{}},
	}
	_, err = ds.Fetch(context.Background(), empty)
	if err == nil {
		t.Fatal("expected error for empty-identity fetch")
	}
	if !strings.Contains(err.Error(), "organization or user") {
		t.Errorf("error %q, want substring %q", err.Error(), "organization or user")
	}
}

// TestUserEntitlementsLua_CacheKey_AllEmptyIdentityFallsBack is the regression test
// for the case where all four identity fields resolve to empty strings. The script
// must return nil so the caching layer falls back to the full input as the key,
// preventing every anonymous request from sharing a single serialised blank-fields entry.
func TestUserEntitlementsLua_CacheKey_AllEmptyIdentityFallsBack(t *testing.T) {
	ds := newCacheOnlyDS(t)

	// Two inputs with no organisation or user claims, distinguished by issuer.
	// Subject.Subject is "" in both, so the username fallback also resolves to "".
	// All four identity fields → "" → Lua returns nil → Go uses full *input.
	anon1 := &service.DataSourceInput{
		Subject: &trust.Result{
			Issuer: "https://idp1.example.com",
			Claims: map[string]any{},
		},
	}
	anon2 := &service.DataSourceInput{
		Subject: &trust.Result{
			Issuer: "https://idp2.example.com",
			Claims: map[string]any{},
		},
	}

	k1 := ds.CacheKey(anon1)
	k2 := ds.CacheKey(anon2)

	if k1.Subject == nil || k2.Subject == nil {
		t.Fatal("expected non-nil Subject in fallback cache keys")
	}
	// Distinct inputs must produce distinct cache keys, not both collapse to the shared blank key.
	if k1.Subject.Issuer == k2.Subject.Issuer {
		t.Errorf("expected distinct cache keys for distinct empty-identity inputs; both have Issuer=%q", k1.Subject.Issuer)
	}
	// The fallback key must not be the blank-fields masked structure (all four keys present with empty values).
	// When Go falls back to *input, the Claims map is the original empty map with no identity keys at all.
	if k1.Subject.Claims != nil {
		if _, hasAcct := k1.Subject.Claims["account_number"]; hasAcct {
			t.Error("got blank-fields cache key for empty-identity input; expected full-input fallback without account_number key")
		}
	}
}

func TestUserEntitlementsLua_MissingConfig(t *testing.T) {
	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:         "user_entitlements",
		Script:       loadUserEntitlementsScript(t),
		ConfigSource: luaservices.NewMapConfigSource(nil),
		HTTPClient:   http.DefaultClient,
	})
	if err != nil {
		t.Fatalf("NewLuaDataSource: %v", err)
	}
	_, err = ds.Fetch(context.Background(), consoleSubjectInput())
	if err == nil || !strings.Contains(err.Error(), "entitlements_api") {
		t.Fatalf("expected entitlements_api error, got %v", err)
	}
}
