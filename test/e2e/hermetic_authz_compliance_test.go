package e2e_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/httpclient"
	"github.com/project-kessel/parsec/internal/httpfixture"
	"github.com/project-kessel/parsec/internal/issuer"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/mapper"
	auditprobe "github.com/project-kessel/parsec/internal/probe/audit"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

const testComplianceBaseURL = "https://export-compliance.example.internal"
const testComplianceAPIURL = testComplianceBaseURL + "/v1/compliance"

// TestHermeticAuthzCompliance covers RHCLOUD-49359: export compliance check
// via Lua data source + redhat_identity.cel.
//
// All I/O is hermetic (fixtures). Tests cover:
//   - CEL opt-out (export_compliance=false) → no compliance call (AC5)
//   - extension absent → check on (AC5 default)
//   - DS not registered → token issued (fail-safe)
//   - blocked result codes → 403 deny (AC4)
//   - compliance service down → fail-open (AC3)
//   - Service account: no compliance check (AC1)
func TestHermeticAuthzCompliance(t *testing.T) {
	fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
	clk := clock.NewFixtureClock(fixedTime)

	jwksFixture, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
		Issuer:  "https://sso.redhat.com/auth/realms/redhat-external",
		JWKSURL: "https://sso.redhat.com/auth/realms/redhat-external/protocol/openid-connect/certs",
		Clock:   clk,
	})
	if err != nil {
		t.Fatalf("JWKS fixture: %v", err)
	}

	celScript, err := os.ReadFile("../../configs/scripts/redhat_identity.cel")
	if err != nil {
		t.Fatalf("read CEL: %v", err)
	}
	luaScript, err := os.ReadFile("../../configs/scripts/export_compliance.lua")
	if err != nil {
		t.Fatalf("read Lua: %v", err)
	}

	celMapper, err := mapper.NewCELMapper(string(celScript), mapper.WithClock(clk))
	if err != nil {
		t.Fatalf("CEL mapper: %v", err)
	}

	identityPolicyDS, err := datasource.NewStaticDataSource("identity-policy", map[string]any{
		"internal_idp_target":   "https://sso.redhat.com/auth/realms/internal",
		"role_fallback_enabled": true,
	})
	if err != nil {
		t.Fatalf("identity-policy DS: %v", err)
	}

	newComplianceDS := func(client *http.Client, obs datasource.DataSourceObserver) service.DataSource {
		ds, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
			Name:   "export_compliance",
			Script: string(luaScript),
			ConfigSource: luaservices.NewMapConfigSource(map[string]any{
				"compliance_api": "/v1/compliance",
			}),
			HTTP:     httpclient.LuaClient{Client: client, BaseURL: testComplianceBaseURL},
			Observer: obs,
		})
		if err != nil {
			t.Fatalf("compliance DS: %v", err)
		}
		return datasource.NewInMemoryCachingDataSource(ds, obs, datasource.WithClock(clk), datasource.WithCacheTTL(time.Minute))
	}

	makeHTTPClient := func(complianceBody string, complianceStatus int) *http.Client {
		return &http.Client{
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
					if fix := jwksFixture.GetFixture(req); fix != nil {
						return fix
					}
					if req.Method == http.MethodGet && req.URL.String() == testComplianceAPIURL {
						return &httpfixture.Fixture{
							StatusCode: complianceStatus,
							Body:       complianceBody,
						}
					}
					return nil
				}),
				Strict: true,
				Clock:  clk,
			}),
		}
	}

	newAuthz := func(withComplianceDS bool, client *http.Client) (*server.AuthzServer, *bytes.Buffer) {
		output := &bytes.Buffer{}
		obs := auditprobe.New(zerolog.New(output), auditprobe.Metadata{ServiceName: "parsec"})
		dsRegistry := service.NewDataSourceRegistry()
		dsRegistry.Register(identityPolicyDS)
		if withComplianceDS {
			dsRegistry.Register(newComplianceDS(client, obs))
		}

		issuerRegistry := service.NewSimpleRegistry()
		issuerRegistry.Register(service.TokenTypeTransactionToken, issuer.NewUnsignedIssuer(issuer.UnsignedIssuerConfig{
			TokenType:    string(service.TokenTypeTransactionToken),
			ClaimMappers: []service.ClaimMapper{celMapper},
			Clock:        clk,
		}))

		tokenService := service.NewTokenService("sso.redhat.com", dsRegistry, issuerRegistry, obs)
		return server.NewAuthzServer(trustStore(t, jwksFixture, client), tokenService, nil, server.DefaultCredentialSources(), nil, nil, obs), output
	}

	consoleClaims := map[string]interface{}{
		"sub":                "user-1",
		"preferred_username": "alice",
		"email":              "alice@example.com",
		"scope":              "api.console openid",
		"idp":                "https://sso.redhat.com/auth/realms/redhat-external",
		"user_id":            "user-1",
		"organization": map[string]interface{}{
			"id":             "org-1",
			"account_number": "12345",
		},
	}

	t.Run("opt-out (export_compliance=false) does not call compliance service", func(t *testing.T) {
		var complianceCalls int
		client := &http.Client{
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
					if fix := jwksFixture.GetFixture(req); fix != nil {
						return fix
					}
					if req.URL.String() == testComplianceAPIURL {
						complianceCalls++
					}
					return nil
				}),
				Strict: false,
				Clock:  clk,
			}),
		}
		authz, _ := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, consoleClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithExportCompliance(token, "false"))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp)
		if complianceCalls != 0 {
			t.Fatalf("expected no compliance HTTP calls when opted out, got %d", complianceCalls)
		}
	})

	t.Run("extension absent → check runs + pass result → token issued", func(t *testing.T) {
		client := makeHTTPClient(`{"result_code":""}`, 200)
		authz, _ := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, consoleClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp)
	})

	t.Run("export_compliance=true + pass result → token issued", func(t *testing.T) {
		client := makeHTTPClient(`{"result_code":""}`, 200)
		authz, _ := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, consoleClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithExportCompliance(token, "true"))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp)
	})

	t.Run("DS not registered + extension absent → token issued", func(t *testing.T) {
		client := makeHTTPClient(`{"result_code":"ERROR_T5"}`, 200)
		authz, _ := newAuthz(false, client)
		token := mustSignToken(t, jwksFixture, consoleClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp)
	})

	t.Run("gate on + pass result code → token issued", func(t *testing.T) {
		client := makeHTTPClient(`{"result_code":""}`, 200)
		authz, _ := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, consoleClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp)
	})

	t.Run("gate on + ERROR_T5 → 403 denied on cache miss and hit", func(t *testing.T) {
		client := makeHTTPClient(`{"result_code":"ERROR_T5"}`, 200)
		authz, output := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, consoleClaims)
		for _, cacheStatus := range []string{"miss", "hit"} {
			output.Reset()
			resp, err := authz.Check(context.Background(), checkRequestWithBearer(token))
			require.NoError(t, err)
			assertComplianceDenied(t, resp)
			records := auditRecords(t, output.String())
			var complianceEvents int
			for _, record := range records {
				if record["event"] == "parsec_auth_compliance_failure" {
					complianceEvents++
					require.Equal(t, "denied", record["outcome"])
					require.Equal(t, "compliance_denied", record["reason_code"])
				}
			}
			require.Equal(t, 1, complianceEvents, "cache %s: %s", cacheStatus, output.String())
			require.Equal(t, "compliance_denied", records[0]["reason_code"])
			resource := records[0]["resource"].(map[string]any)
			require.Equal(t, cacheStatus, resource["cache_status"])
			require.NotContains(t, resource, "token_types")
		}
	})

	t.Run("gate on + ERROR_EXPORT_CONTROL → 403 denied", func(t *testing.T) {
		client := makeHTTPClient(`{"result_code":"ERROR_EXPORT_CONTROL"}`, 200)
		authz, _ := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, consoleClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertComplianceDenied(t, resp)
	})

	t.Run("gate on + ERROR_OFAC → 403 denied", func(t *testing.T) {
		client := makeHTTPClient(`{"result_code":"ERROR_OFAC"}`, 200)
		authz, _ := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, consoleClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertComplianceDenied(t, resp)
	})

	t.Run("gate on + unknown result code → token issued (not in error list)", func(t *testing.T) {
		client := makeHTTPClient(`{"result_code":"UNKNOWN_CODE"}`, 200)
		authz, _ := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, consoleClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp)
	})

	t.Run("gate on + compliance service down → fail-open token issued (AC3)", func(t *testing.T) {
		client := makeHTTPClient(`{"error":"unavailable"}`, 503)
		authz, _ := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, consoleClaims)
		resp, err := authz.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp) // fail-open
	})

	t.Run("service account: no compliance check (AC1)", func(t *testing.T) {
		var complianceCalls int
		client := &http.Client{
			Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
				Provider: httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
					if fix := jwksFixture.GetFixture(req); fix != nil {
						return fix
					}
					if req.URL.String() == testComplianceAPIURL {
						complianceCalls++
					}
					return nil
				}),
				Strict: false,
				Clock:  clk,
			}),
		}
		authz, _ := newAuthz(true, client)
		token := mustSignToken(t, jwksFixture, map[string]interface{}{
			"preferred_username": "service-account-myapp",
			"client_id":          "myapp",
			"sub":                "abc-123",
			"scope":              "api.console openid",
			"organization": map[string]interface{}{
				"id":             "org-1",
				"account_number": "12345",
			},
		})
		resp, err := authz.Check(context.Background(), checkRequestWithBearer(token))
		if err != nil {
			t.Fatalf("Check: %v", err)
		}
		assertOKResponse(t, resp)
		if complianceCalls != 0 {
			t.Fatalf("expected no compliance calls for service account, got %d", complianceCalls)
		}
	})
}

// trustStore builds a stub trust store using the provided JWKS fixture and HTTP client.
func trustStore(t *testing.T, jwks *httpfixture.JWKSFixture, client *http.Client) trust.Store {
	t.Helper()
	clk := clock.NewFixtureClock(time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC))
	jwtValidator, err := trust.NewJWTValidator(trust.JWTValidatorConfig{
		Issuer:      jwks.Issuer(),
		JWKSURL:     jwks.JWKSURL(),
		TrustDomain: "https://sso.redhat.com/auth/realms/redhat-external",
		HTTPClient:  client,
		Clock:       clk,
	})
	if err != nil {
		t.Fatalf("JWT validator: %v", err)
	}
	store := trust.NewStubStore()
	store.AddValidator(jwtValidator)
	return store
}

func checkRequestWithExportCompliance(token, value string) *authv3.CheckRequest {
	req := checkRequestWithBearer(token)
	req.Attributes.ContextExtensions = map[string]string{
		"export_compliance": value,
	}
	return req
}

// assertComplianceDenied verifies a 403 PermissionDenied response from the compliance check.
func assertComplianceDenied(t *testing.T, resp *authv3.CheckResponse) {
	t.Helper()
	if resp.Status.Code == int32(codes.OK) {
		t.Fatal("expected denied response, got OK")
	}
	deniedResp := resp.GetDeniedResponse()
	if deniedResp == nil {
		t.Fatal("expected DeniedHttpResponse")
	}
	if deniedResp.Status.Code != 403 {
		t.Errorf("expected HTTP 403, got %d", deniedResp.Status.Code)
	}
}

// auditRecords reads the externally emitted JSON audit stream.
func auditRecords(t *testing.T, output string) []map[string]any {
	t.Helper()
	var records []map[string]any
	for _, line := range strings.Split(strings.TrimSpace(output), "\n") {
		var record map[string]any
		require.NoError(t, json.Unmarshal([]byte(line), &record))
		records = append(records, record)
	}
	return records
}
