package server

import (
	"context"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestAuthzServer_Check_ScopeResolution(t *testing.T) {
	ctx := context.Background()

	t.Run("no scope config omits scope", func(t *testing.T) {
		authzServer, stubValidator, fakeObs := setupAuthzServerWithScopePolicy(t, ScopePolicy{})
		stubValidator.WithResult(&trust.Result{
			Subject:     "user-123",
			TrustDomain: "parsec.test",
		})

		_, err := authzServer.Check(ctx, authzCheckRequest("Bearer valid-token", "/api/resource", nil))
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}

		assertTokenIssuanceScope(t, fakeObs, "")
	})

	t.Run("default scope config", func(t *testing.T) {
		policy, err := newScopePolicyFromMaps("configured-default", nil, "", "")
		if err != nil {
			t.Fatalf("newScopePolicyFromMaps: %v", err)
		}
		authzServer, stubValidator, fakeObs := setupAuthzServerWithScopePolicy(t, policy)
		stubValidator.WithResult(&trust.Result{
			Subject:     "user-123",
			TrustDomain: "parsec.test",
		})

		_, err = authzServer.Check(ctx, authzCheckRequest("Bearer valid-token", "/api/resource", nil))
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}

		assertTokenIssuanceScope(t, fakeObs, "configured-default")
	})

	t.Run("request header overrides default", func(t *testing.T) {
		policy, err := newScopePolicyFromMaps("configured-default", nil, "x-oauth-scope", "")
		if err != nil {
			t.Fatalf("newScopePolicyFromMaps: %v", err)
		}
		authzServer, stubValidator, fakeObs := setupAuthzServerWithScopePolicy(t, policy)
		stubValidator.WithResult(&trust.Result{
			Subject:     "user-123",
			TrustDomain: "parsec.test",
		})

		resp, err := authzServer.Check(ctx, authzCheckRequest("Bearer valid-token", "/api/resource", map[string]string{
			"x-oauth-scope": "header-scope",
		}))
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}

		assertTokenIssuanceScope(t, fakeObs, "header-scope")

		reqCtx, err := parseTestTokenRequestContext(transactionTokenFromCheckResponse(t, resp))
		if err != nil {
			t.Fatalf("parseTestTokenRequestContext: %v", err)
		}
		if got, ok := reqCtx["resolved_scope_source"].(string); !ok || got != "request_header" {
			t.Fatalf("resolved_scope_source = %v, want %q", reqCtx["resolved_scope_source"], "request_header")
		}
	})

	t.Run("request query param overrides default", func(t *testing.T) {
		policy, err := newScopePolicyFromMaps("configured-default", nil, "", "scope")
		if err != nil {
			t.Fatalf("newScopePolicyFromMaps: %v", err)
		}
		authzServer, stubValidator, fakeObs := setupAuthzServerWithScopePolicy(t, policy)
		stubValidator.WithResult(&trust.Result{
			Subject:     "user-123",
			TrustDomain: "parsec.test",
		})

		resp, err := authzServer.Check(ctx, authzCheckRequest("Bearer valid-token", "/api/resource?scope=query-scope", nil))
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}

		assertTokenIssuanceScope(t, fakeObs, "query-scope")

		reqCtx, err := parseTestTokenRequestContext(transactionTokenFromCheckResponse(t, resp))
		if err != nil {
			t.Fatalf("parseTestTokenRequestContext: %v", err)
		}
		if got, ok := reqCtx["resolved_scope_source"].(string); !ok || got != "request_query" {
			t.Fatalf("resolved_scope_source = %v, want %q", reqCtx["resolved_scope_source"], "request_query")
		}
	})

	t.Run("by trust domain mapping", func(t *testing.T) {
		policy, err := newScopePolicyFromMaps("configured-default", map[string]string{
			"customer.example.com": "customer:access",
		}, "", "")
		if err != nil {
			t.Fatalf("newScopePolicyFromMaps: %v", err)
		}
		authzServer, stubValidator, fakeObs := setupAuthzServerWithScopePolicy(t, policy)
		stubValidator.WithResult(&trust.Result{
			Subject:     "user-123",
			TrustDomain: "customer.example.com",
		})

		_, err = authzServer.Check(ctx, authzCheckRequest("Bearer valid-token", "/api/resource", nil))
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}

		assertTokenIssuanceScope(t, fakeObs, "customer:access")
	})
}

func setupAuthzServerWithScopePolicy(t *testing.T, scopePolicy ScopePolicy) (*AuthzServer, *trust.StubValidator, *service.FakeObserver) {
	t.Helper()

	trustStore, stubValidator, tokenService, fakeObs := setupScopeTestDependencies(t)
	authzServer := NewAuthzServer(trustStore, tokenService, nil, scopePolicy, nil)
	return authzServer, stubValidator, fakeObs
}

func authzCheckRequest(authHeader, path string, extraHeaders map[string]string) *authv3.CheckRequest {
	headers := map[string]string{
		"authorization": authHeader,
	}
	for key, value := range extraHeaders {
		headers[key] = value
	}

	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  "GET",
					Path:    path,
					Headers: headers,
				},
			},
		},
	}
}

func transactionTokenFromCheckResponse(t *testing.T, resp *authv3.CheckResponse) string {
	t.Helper()

	okResp := resp.GetOkResponse()
	if okResp == nil {
		t.Fatal("expected OK response, got nil")
	}

	for _, header := range okResp.Headers {
		if header.Header.Key == "Transaction-Token" {
			return header.Header.Value
		}
	}

	t.Fatal("transaction token header not found")
	return ""
}
