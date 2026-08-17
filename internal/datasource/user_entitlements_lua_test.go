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

func TestUserEntitlementsLua_CacheKey(t *testing.T) {
	ds, err := NewCacheableLuaDataSource(CacheableLuaDataSourceConfig{
		Name:         "user_entitlements",
		Script:       loadUserEntitlementsScript(t),
		ConfigSource: luaservices.NewMapConfigSource(map[string]any{"entitlements_api": "https://entitlements.example.internal/api/entitlements/v1/services"}),
		HTTPClient:   http.DefaultClient,
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}

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
	if masked.Subject.Subject != "" {
		t.Errorf("cache key should not include subject id, got %q", masked.Subject.Subject)
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
