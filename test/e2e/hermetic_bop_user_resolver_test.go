package e2e_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"google.golang.org/grpc/metadata"

	parsecv1 "github.com/project-kessel/parsec/api/gen/parsec/v1"
	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/httpfixture"
	"github.com/project-kessel/parsec/internal/issuer"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

type staticDataSource struct {
	name string
	data any
}

func (s *staticDataSource) Name() string { return s.name }

func (s *staticDataSource) Fetch(_ context.Context, _ *service.DataSourceInput) (*service.DataSourceResult, error) {
	b, err := json.Marshal(s.data)
	if err != nil {
		return nil, err
	}
	return &service.DataSourceResult{
		Data:        b,
		ContentType: service.ContentTypeJSON,
	}, nil
}

func readBOPScript(t *testing.T) string {
	t.Helper()
	return readScript(t, "bop_user_resolver.lua")
}

func readRedHatIdentityCEL(t *testing.T) string {
	t.Helper()
	return readScript(t, "redhat_identity.cel")
}

func readScript(t *testing.T, name string) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	scriptPath := filepath.Join(filepath.Dir(thisFile), "..", "..", "configs", "scripts", name)
	b, err := os.ReadFile(scriptPath)
	if err != nil {
		t.Fatalf("failed to read %s: %v", name, err)
	}
	return string(b)
}

// TestHermeticBOPUserResolver tests the BOP user resolver flow through the
// token exchange API. A plain username is provided as the subject_token, the
// BOP Lua validator resolves it to a full user object, and tokens are issued.
func TestHermeticBOPUserResolver(t *testing.T) {
	// ============================================================
	// 1. Setup Fixtures
	// ============================================================

	fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
	clk := clock.NewFixtureClock(fixedTime)

	bopURL := "https://example.bop.redhat.com"

	bopUserResponse := `[{
		"id": "12345",
		"org_id": "67890",
		"account_number": "11111",
		"email": "alice@example.com",
		"first_name": "Alice",
		"last_name": "Developer",
		"username": "alice",
		"is_org_admin": true,
		"is_internal": false,
		"is_active": true,
		"locale": "en_US"
	}]`

	// JWKS fixture for actor authentication
	actorJWKS, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
		Issuer:  "https://auth.internal.example.com",
		JWKSURL: "https://auth.internal.example.com/.well-known/jwks.json",
		Clock:   clk,
	})
	if err != nil {
		t.Fatalf("failed to create actor JWKS fixture: %v", err)
	}

	bopFixture := httpfixture.NewRuleBasedProvider([]httpfixture.HTTPFixtureRule{
		{
			Request: httpfixture.FixtureRequest{
				Method:  "POST",
				URL:     bopURL + "/v1/users.*",
				URLType: "pattern",
			},
			Response: httpfixture.Fixture{
				StatusCode: 200,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       bopUserResponse,
			},
		},
	})

	allFixtures := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		if f := actorJWKS.GetFixture(req); f != nil {
			return f
		}
		if f := bopFixture.GetFixture(req); f != nil {
			if req.Body != nil {
				var payload map[string][]string
				if err := json.NewDecoder(req.Body).Decode(&payload); err != nil {
					t.Errorf("BOP request body decode: %v", err)
				} else if len(payload["users"]) == 0 {
					t.Errorf("BOP request body missing 'users' field")
				}
			}
			return f
		}
		return nil
	})

	httpClient := &http.Client{
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: allFixtures,
			Strict:   true,
			Clock:    clk,
		}),
	}

	// ============================================================
	// 2. Build Components
	// ============================================================

	actorValidator, err := trust.NewJWTValidator(trust.JWTValidatorConfig{
		Issuer:      actorJWKS.Issuer(),
		JWKSURL:     actorJWKS.JWKSURL(),
		TrustDomain: "internal.example.com",
		HTTPClient:  httpClient,
		Clock:       clk,
	})
	if err != nil {
		t.Fatalf("failed to create actor validator: %v", err)
	}

	bopScript := readBOPScript(t)

	bopValidator, err := trust.NewLuaValidator(
		"bop-user-resolver",
		bopScript,
		[]trust.CredentialType{trust.CredentialTypeBearer},
		trust.WithLuaHTTPClient(httpClient),
		trust.WithLuaConfigSource(luaservices.NewMapConfigSource(map[string]any{
			"bop_url":      bopURL,
			"users_path":   "/v1/users",
			"trust_domain": "bop.redhat.com",
			"api_token":    "test-token",
			"client_id":    "test-client",
			"environment":  "test",
		})),
	)
	if err != nil {
		t.Fatalf("failed to create BOP Lua validator: %v", err)
	}

	trustStore := trust.NewStubStore()
	trustStore.AddValidator(actorValidator)
	trustStore.AddValidator(bopValidator)

	identityCEL := readRedHatIdentityCEL(t)
	celMapper, err := mapper.NewCELMapper(identityCEL, mapper.WithClock(clk))
	if err != nil {
		t.Fatalf("failed to create CEL mapper: %v", err)
	}

	claimMappers := []service.ClaimMapper{celMapper}

	rhIdentityIssuer := issuer.NewUnsignedIssuer(issuer.UnsignedIssuerConfig{
		TokenType:    string(service.TokenTypeRHIdentity),
		ClaimMappers: claimMappers,
		Clock:        clk,
	})

	txnIssuer := issuer.NewUnsignedIssuer(issuer.UnsignedIssuerConfig{
		TokenType:    string(service.TokenTypeTransactionToken),
		ClaimMappers: claimMappers,
		Clock:        clk,
	})

	issuerRegistry := service.NewSimpleRegistry()
	issuerRegistry.Register(service.TokenTypeRHIdentity, rhIdentityIssuer)
	issuerRegistry.Register(service.TokenTypeTransactionToken, txnIssuer)

	dsRegistry := service.NewDataSourceRegistry()
	dsRegistry.Register(&staticDataSource{
		name: "identity-policy",
		data: map[string]any{
			"internal_idp_target":   "https://sso.redhat.com/auth/realms/internal",
			"role_fallback_enabled": false,
		},
	})

	tokenService := service.NewTokenService("parsec.example.com", dsRegistry, issuerRegistry, nil)
	claimsFilterRegistry := server.NewStubClaimsFilterRegistry()

	exchangeServer := server.NewExchangeServer(trustStore, tokenService, claimsFilterRegistry, server.DefaultCredentialSources(), nil)

	// ============================================================
	// 3. Test Cases
	// ============================================================

	t.Run("issues rh-identity with correct BOP envelope", func(t *testing.T) {
		actorToken, err := actorJWKS.CreateAndSignToken(map[string]interface{}{
			"sub":   "api-gateway",
			"scope": "token:exchange",
		})
		if err != nil {
			t.Fatalf("failed to create actor token: %v", err)
		}

		ctx := metadata.NewIncomingContext(
			context.Background(),
			metadata.Pairs("authorization", "Bearer "+actorToken),
		)

		resp, err := exchangeServer.Exchange(ctx, &parsecv1.ExchangeRequest{
			GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
			Audience:           "parsec.example.com",
			RequestedTokenType: string(service.TokenTypeRHIdentity),
			SubjectToken:       "alice",
			SubjectTokenType:   "urn:ietf:params:oauth:token-type:access_token",
		})
		if err != nil {
			t.Fatalf("Exchange RPC failed: %v", err)
		}

		if resp.AccessToken == "" {
			t.Fatal("expected non-empty access_token")
		}
		if resp.IssuedTokenType != string(service.TokenTypeRHIdentity) {
			t.Errorf("IssuedTokenType=%s, want %s", resp.IssuedTokenType, service.TokenTypeRHIdentity)
		}

		tokenJSON, err := base64.StdEncoding.DecodeString(resp.AccessToken)
		if err != nil {
			t.Fatalf("failed to decode token: %v", err)
		}

		var envelope map[string]any
		if err := json.Unmarshal(tokenJSON, &envelope); err != nil {
			t.Fatalf("failed to parse token JSON: %v", err)
		}

		identity, ok := envelope["identity"].(map[string]any)
		if !ok {
			t.Fatalf("expected 'identity' to be a map, got %T", envelope["identity"])
		}

		if identity["auth_type"] != "jwt-auth" {
			t.Errorf("auth_type=%v, want jwt-auth", identity["auth_type"])
		}
		if identity["type"] != "User" {
			t.Errorf("type=%v, want User", identity["type"])
		}
		if identity["org_id"] != "67890" {
			t.Errorf("org_id=%v, want 67890", identity["org_id"])
		}
		if identity["account_number"] != "11111" {
			t.Errorf("account_number=%v, want 11111", identity["account_number"])
		}

		user, ok := identity["user"].(map[string]any)
		if !ok {
			t.Fatalf("expected 'user' to be a map, got %T", identity["user"])
		}
		if user["username"] != "alice" {
			t.Errorf("username=%v, want alice", user["username"])
		}
		if user["email"] != "alice@example.com" {
			t.Errorf("email=%v, want alice@example.com", user["email"])
		}
		if user["first_name"] != "Alice" {
			t.Errorf("first_name=%v, want Alice", user["first_name"])
		}
		if user["last_name"] != "Developer" {
			t.Errorf("last_name=%v, want Developer", user["last_name"])
		}
		if user["is_org_admin"] != true {
			t.Errorf("is_org_admin=%v, want true", user["is_org_admin"])
		}
		if user["is_internal"] != false {
			t.Errorf("is_internal=%v, want false", user["is_internal"])
		}
		if user["is_active"] != true {
			t.Errorf("is_active=%v, want true", user["is_active"])
		}
		if user["user_id"] != "12345" {
			t.Errorf("user_id=%v, want 12345", user["user_id"])
		}

		internal, ok := identity["internal"].(map[string]any)
		if !ok {
			t.Fatalf("expected 'internal' to be a map, got %T", identity["internal"])
		}
		if internal["org_id"] != "67890" {
			t.Errorf("internal.org_id=%v, want 67890", internal["org_id"])
		}
		if internal["cross_access"] != false {
			t.Errorf("internal.cross_access=%v, want false", internal["cross_access"])
		}

		if _, hasEntitlements := envelope["entitlements"]; hasEntitlements {
			t.Error("BOP identity envelope must not contain entitlements key")
		}
	})

	t.Run("rejects unknown username", func(t *testing.T) {
		emptyBOPFixture := httpfixture.NewRuleBasedProvider([]httpfixture.HTTPFixtureRule{
			{
				Request: httpfixture.FixtureRequest{
					Method:  "POST",
					URL:     bopURL + "/v1/users.*",
					URLType: "pattern",
				},
				Response: httpfixture.Fixture{
					StatusCode: 200,
					Headers:    map[string]string{"Content-Type": "application/json"},
					Body:       `[]`,
				},
			},
		})

		emptyFixtures := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
			if f := actorJWKS.GetFixture(req); f != nil {
				return f
			}
			return emptyBOPFixture.GetFixture(req)
		})

		emptyHTTPClient := &http.Client{
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: emptyFixtures,
				Strict:   true,
				Clock:    clk,
			}),
		}

		emptyValidator, err := trust.NewLuaValidator(
			"bop-empty",
			bopScript,
			[]trust.CredentialType{trust.CredentialTypeBearer},
			trust.WithLuaHTTPClient(emptyHTTPClient),
			trust.WithLuaConfigSource(luaservices.NewMapConfigSource(map[string]any{
				"bop_url":      bopURL,
				"users_path":   "/v1/users",
				"trust_domain": "bop.redhat.com",
				"api_token":    "test-token",
				"client_id":    "test-client",
				"environment":  "test",
			})),
		)
		if err != nil {
			t.Fatalf("failed to create empty BOP validator: %v", err)
		}

		emptyStore := trust.NewStubStore()
		emptyStore.AddValidator(actorValidator)
		emptyStore.AddValidator(emptyValidator)

		emptyExchange := server.NewExchangeServer(emptyStore, tokenService, claimsFilterRegistry, server.DefaultCredentialSources(), nil)

		actorToken, err := actorJWKS.CreateAndSignToken(map[string]interface{}{
			"sub": "api-gateway",
		})
		if err != nil {
			t.Fatalf("failed to create actor token: %v", err)
		}

		ctx := metadata.NewIncomingContext(
			context.Background(),
			metadata.Pairs("authorization", "Bearer "+actorToken),
		)

		_, err = emptyExchange.Exchange(ctx, &parsecv1.ExchangeRequest{
			GrantType:          "urn:ietf:params:oauth:grant-type:token-exchange",
			Audience:           "parsec.example.com",
			RequestedTokenType: string(service.TokenTypeTransactionToken),
			SubjectToken:       "nonexistent",
			SubjectTokenType:   "urn:ietf:params:oauth:token-type:access_token",
		})
		if err == nil {
			t.Fatal("expected error for unknown username, got nil")
		}
	})
}
