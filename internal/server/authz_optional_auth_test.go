package server

import (
	"context"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/issuer"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestAuthzServer_AnonymousSubjectPolicy(t *testing.T) {
	ctx := context.Background()

	setup := func(t *testing.T, celScript string) (*AuthzServer, *trust.StubValidator) {
		t.Helper()

		trustStore := trust.NewStubStore()
		stubValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
		trustStore.AddValidator(stubValidator)

		dataSourceRegistry := service.NewDataSourceRegistry()
		issuerRegistry := service.NewSimpleRegistry()
		txnMappers := []service.ClaimMapper{service.NewPassthroughSubjectMapper()}
		reqMappers := []service.ClaimMapper{service.NewRequestAttributesMapper()}
		txnTokenIssuer := issuer.NewStubIssuer(issuer.StubIssuerConfig{
			IssuerURL:                 "https://parsec.test",
			TTL:                       5 * time.Minute,
			TransactionContextMappers: txnMappers,
			RequestContextMappers:     reqMappers,
		})
		issuerRegistry.Register(service.TokenTypeTransactionToken, txnTokenIssuer)
		tokenService := service.NewTokenService("parsec.test", dataSourceRegistry, issuerRegistry, nil)

		var opts []AuthzOption
		if celScript != "" {
			policy, err := NewCelAnonymousSubjectPolicy(celScript)
			if err != nil {
				t.Fatalf("failed to create CEL policy: %v", err)
			}
			opts = append(opts, WithAnonymousSubjectPolicy(policy))
		}

		srv := NewAuthzServer(trustStore, tokenService, nil, nil, opts...)
		return srv, stubValidator
	}

	makeReq := func(method, path, authHeader string) *authv3.CheckRequest {
		headers := map[string]string{}
		if authHeader != "" {
			headers["authorization"] = authHeader
		}
		return &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method:  method,
						Path:    path,
						Headers: headers,
					},
				},
			},
		}
	}

	makeReqWithExtensions := func(method, path string, extensions map[string]string) *authv3.CheckRequest {
		return &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method:  method,
						Path:    path,
						Headers: map[string]string{},
					},
				},
				ContextExtensions: extensions,
			},
		}
	}

	t.Run("default policy denies when no credentials", func(t *testing.T) {
		trustStore := trust.NewStubStore()
		trustStore.AddValidator(trust.NewStubValidator(trust.CredentialTypeBearer))
		dataSourceRegistry := service.NewDataSourceRegistry()
		issuerRegistry := service.NewSimpleRegistry()
		tokenService := service.NewTokenService("parsec.test", dataSourceRegistry, issuerRegistry, nil)

		srv := NewAuthzServer(trustStore, tokenService, nil, nil)

		resp, err := srv.Check(ctx, makeReq("GET", "/anything", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code == 0 {
			t.Error("expected denial when no policy configured and no credentials, got OK")
		}
	})

	t.Run("CEL path policy allows matching path", func(t *testing.T) {
		srv, _ := setup(t, `request.path.startsWith("/public/")`)

		resp, err := srv.Check(ctx, makeReq("GET", "/public/docs", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != 0 {
			t.Errorf("expected OK for matching path, got code %d: %s", resp.Status.Code, resp.Status.Message)
		}

		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OK response")
		}
		if len(okResp.Headers) != 0 {
			t.Errorf("expected no token headers on anonymous pass-through, got %d", len(okResp.Headers))
		}
	})

	t.Run("CEL path policy denies non-matching path", func(t *testing.T) {
		srv, _ := setup(t, `request.path.startsWith("/public/")`)

		resp, err := srv.Check(ctx, makeReq("GET", "/api/protected", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code == 0 {
			t.Error("expected denial for non-matching path, got OK")
		}
	})

	t.Run("credentials present on policy-allowed path issues tokens", func(t *testing.T) {
		srv, _ := setup(t, `request.path.startsWith("/public/")`)

		resp, err := srv.Check(ctx, makeReq("GET", "/public/docs", "Bearer valid-token"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != 0 {
			t.Errorf("expected OK, got code %d: %s", resp.Status.Code, resp.Status.Message)
		}

		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OK response")
		}

		foundToken := false
		for _, header := range okResp.Headers {
			if header.Header.Key == "Transaction-Token" {
				foundToken = true
			}
		}
		if !foundToken {
			t.Error("expected Transaction-Token header when credentials provided")
		}
	})

	t.Run("invalid credentials on policy-allowed path still denies", func(t *testing.T) {
		srv, stubValidator := setup(t, `request.path.startsWith("/public/")`)
		stubValidator.WithError(trust.ErrInvalidToken)
		defer stubValidator.WithError(nil)

		resp, err := srv.Check(ctx, makeReq("GET", "/public/docs", "Bearer bad-token"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code == 0 {
			t.Error("expected denial for invalid credentials, got OK")
		}
	})

	t.Run("CEL method+path policy", func(t *testing.T) {
		srv, _ := setup(t, `request.method == "GET" && request.path == "/health"`)

		resp, err := srv.Check(ctx, makeReq("GET", "/health", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != 0 {
			t.Errorf("expected OK for GET /health, got code %d", resp.Status.Code)
		}

		resp, err = srv.Check(ctx, makeReq("POST", "/health", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code == 0 {
			t.Error("expected denial for POST /health, got OK")
		}
	})

	t.Run("CEL regex pattern", func(t *testing.T) {
		srv, _ := setup(t, `request.path.matches("^/api/[^/]+/v[0-9]+/openapi\\.json$")`)

		resp, err := srv.Check(ctx, makeReq("GET", "/api/insights/v1/openapi.json", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != 0 {
			t.Errorf("expected OK for regex-matching path, got code %d", resp.Status.Code)
		}

		resp, err = srv.Check(ctx, makeReq("GET", "/api/protected/resource", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code == 0 {
			t.Error("expected denial for non-regex-matching path, got OK")
		}
	})

	t.Run("CEL with context_extensions", func(t *testing.T) {
		srv, _ := setup(t, `has(request.additional.context_extensions) && request.additional.context_extensions.optional_auth == "true"`)

		resp, err := srv.Check(ctx, makeReqWithExtensions("GET", "/any/path", map[string]string{
			"optional_auth": "true",
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != 0 {
			t.Errorf("expected OK when context_extensions allows, got code %d", resp.Status.Code)
		}

		resp, err = srv.Check(ctx, makeReqWithExtensions("GET", "/any/path", map[string]string{
			"optional_auth": "false",
		}))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code == 0 {
			t.Error("expected denial when context_extensions does not allow, got OK")
		}
	})

	t.Run("path traversal does not bypass CEL policy", func(t *testing.T) {
		srv, _ := setup(t, `request.path.startsWith("/public/")`)

		bypassPaths := []string{
			"/public/../secret",
			"/public/%2e%2e/secret",
			"/public%2fdocs",
			"/public//docs",
		}
		for _, p := range bypassPaths {
			resp, err := srv.Check(ctx, makeReq("GET", p, ""))
			if err != nil {
				t.Fatalf("path %q: unexpected error: %v", p, err)
			}
			if resp.Status.Code == 0 {
				t.Errorf("path %q: expected denial for traversal attempt, got OK", p)
			}
		}
	})

	t.Run("query string stripped before CEL evaluation", func(t *testing.T) {
		srv, _ := setup(t, `request.path == "/openapi.json"`)

		resp, err := srv.Check(ctx, makeReq("GET", "/openapi.json?version=2", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != 0 {
			t.Errorf("expected OK with query string stripped, got code %d", resp.Status.Code)
		}
	})

	t.Run("unsupported auth scheme denies even on policy-allowed path", func(t *testing.T) {
		srv, _ := setup(t, `request.path == "/openapi.json"`)

		resp, err := srv.Check(ctx, makeReq("GET", "/openapi.json", "Basic dXNlcjpwYXNz"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code == 0 {
			t.Error("expected denial for unsupported auth scheme, got OK")
		}
	})
}

func TestAuthzServer_AnonymousSubjectPolicy_Observability(t *testing.T) {
	ctx := context.Background()

	t.Run("anonymous subject allowed fires correct probe sequence", func(t *testing.T) {
		fakeObs := service.NewFakeObserver(t)

		trustStore := trust.NewStubStore()
		dataSourceRegistry := service.NewDataSourceRegistry()
		issuerRegistry := service.NewSimpleRegistry()
		tokenService := service.NewTokenService("parsec.test", dataSourceRegistry, issuerRegistry, nil)

		policy, _ := NewCelAnonymousSubjectPolicy(`request.path == "/openapi.json"`)
		srv := NewAuthzServer(trustStore, tokenService, nil, fakeObs,
			WithAnonymousSubjectPolicy(policy))

		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method:  "GET",
						Path:    "/openapi.json",
						Headers: map[string]string{},
					},
				},
			},
		}

		_, err := srv.Check(ctx, req)
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}

		p := fakeObs.AssertSingleProbe("AuthzCheckStarted", nil)
		p.AssertProbeSequence(
			"RequestAttributesParsed",
			"ActorValidationSucceeded",
			"AnonymousSubjectDetected",
			"AnonymousSubjectPolicyAllowed",
			"End",
		)
	})

	t.Run("anonymous subject denied fires correct probe sequence", func(t *testing.T) {
		fakeObs := service.NewFakeObserver(t)

		trustStore := trust.NewStubStore()
		dataSourceRegistry := service.NewDataSourceRegistry()
		issuerRegistry := service.NewSimpleRegistry()
		tokenService := service.NewTokenService("parsec.test", dataSourceRegistry, issuerRegistry, nil)

		srv := NewAuthzServer(trustStore, tokenService, nil, fakeObs)

		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method:  "GET",
						Path:    "/anything",
						Headers: map[string]string{},
					},
				},
			},
		}

		_, err := srv.Check(ctx, req)
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}

		p := fakeObs.AssertSingleProbe("AuthzCheckStarted", nil)
		p.AssertProbeSequence(
			"RequestAttributesParsed",
			"ActorValidationSucceeded",
			"AnonymousSubjectDetected",
			"AnonymousSubjectPolicyDenied",
			"End",
		)
	})
}
