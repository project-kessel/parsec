package server

import (
	"context"
	"errors"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/issuer"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

type erroringValidatorFilter struct{}

func (erroringValidatorFilter) IsAllowed(context.Context, *trust.Result, string, *request.RequestAttributes) (bool, error) {
	return false, errors.New("filter evaluation failed")
}

func TestAuthzServer_OptionalAuth(t *testing.T) {
	ctx := context.Background()

	setup := func(t *testing.T, patterns ...request.PathPattern) (*AuthzServer, *trust.StubValidator) {
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

		matcher, err := request.NewPathMatcher(patterns)
		if err != nil {
			t.Fatalf("failed to create path matcher: %v", err)
		}

		srv := NewAuthzServer(trustStore, tokenService, nil, nil,
			WithOptionalAuthPathMatcher(matcher))
		return srv, stubValidator
	}

	makeReq := func(path, authHeader string) *authv3.CheckRequest {
		headers := map[string]string{}
		if authHeader != "" {
			headers["authorization"] = authHeader
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

	t.Run("optional path without credentials allows through", func(t *testing.T) {
		srv, _ := setup(t, request.PathPattern{Path: "/openapi.json", Match: "exact"})

		resp, err := srv.Check(ctx, makeReq("/openapi.json", ""))
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
		if len(okResp.Headers) != 0 {
			t.Errorf("expected no headers on unauthenticated pass-through, got %d", len(okResp.Headers))
		}
		if len(okResp.HeadersToRemove) != 0 {
			t.Errorf("expected no headers to remove, got %v", okResp.HeadersToRemove)
		}
	})

	t.Run("optional path with valid credentials issues tokens", func(t *testing.T) {
		srv, _ := setup(t, request.PathPattern{Path: "/openapi.json", Match: "exact"})

		resp, err := srv.Check(ctx, makeReq("/openapi.json", "Bearer valid-token"))
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
			t.Error("expected Transaction-Token header when credentials provided on optional path")
		}

		foundAuthRemoval := false
		for _, h := range okResp.HeadersToRemove {
			if h == "authorization" {
				foundAuthRemoval = true
			}
		}
		if !foundAuthRemoval {
			t.Error("expected authorization in headers to remove")
		}
	})

	t.Run("optional path with invalid credentials denies", func(t *testing.T) {
		srv, stubValidator := setup(t, request.PathPattern{Path: "/openapi.json", Match: "exact"})
		stubValidator.WithError(trust.ErrInvalidToken)
		defer stubValidator.WithError(nil)

		resp, err := srv.Check(ctx, makeReq("/openapi.json", "Bearer bad-token"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code == 0 {
			t.Error("expected denial for invalid credentials on optional path, got OK")
		}
	})

	t.Run("protected path without credentials denies", func(t *testing.T) {
		srv, _ := setup(t, request.PathPattern{Path: "/openapi.json", Match: "exact"})

		resp, err := srv.Check(ctx, makeReq("/api/resource", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code == 0 {
			t.Error("expected denial for missing credentials on protected path, got OK")
		}
	})

	t.Run("glob pattern matches", func(t *testing.T) {
		srv, _ := setup(t, request.PathPattern{Path: "/api/*.json", Match: "glob"})

		resp, err := srv.Check(ctx, makeReq("/api/foo.json", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != 0 {
			t.Errorf("expected OK for glob match, got code %d: %s", resp.Status.Code, resp.Status.Message)
		}

		resp, err = srv.Check(ctx, makeReq("/api/resource", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code == 0 {
			t.Error("expected denial for non-matching glob path, got OK")
		}
	})

	t.Run("prefix match", func(t *testing.T) {
		srv, _ := setup(t, request.PathPattern{Path: "/api/docs/", Match: "prefix"})

		resp, err := srv.Check(ctx, makeReq("/api/docs/openapi.json", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != 0 {
			t.Errorf("expected OK for prefix match, got code %d", resp.Status.Code)
		}

		resp, err = srv.Check(ctx, makeReq("/api/docs-extra", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code == 0 {
			t.Error("expected denial for path not matching prefix /api/docs/, got OK")
		}
	})

	t.Run("gRPC exact path without credentials allows through", func(t *testing.T) {
		srv, _ := setup(t, request.PathPattern{Path: "/test.v1.FooService/Bar", Match: "exact"})

		resp, err := srv.Check(ctx, makeReq("/test.v1.FooService/Bar", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != 0 {
			t.Errorf("expected OK for gRPC optional path, got code %d", resp.Status.Code)
		}
	})

	t.Run("gRPC prefix path without credentials allows through", func(t *testing.T) {
		srv, _ := setup(t, request.PathPattern{Path: "/grpc.health.v1.Health/", Match: "prefix"})

		resp, err := srv.Check(ctx, makeReq("/grpc.health.v1.Health/Check", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != 0 {
			t.Errorf("expected OK for gRPC health prefix, got code %d", resp.Status.Code)
		}
	})

	t.Run("protected gRPC path without credentials denies", func(t *testing.T) {
		srv, _ := setup(t, request.PathPattern{Path: "/test.v1.FooService/Bar", Match: "exact"})

		resp, err := srv.Check(ctx, makeReq("/test.v1.SecureService/Baz", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code == 0 {
			t.Error("expected denial for protected gRPC path, got OK")
		}
	})

	t.Run("unsupported auth scheme on optional path denies", func(t *testing.T) {
		srv, _ := setup(t, request.PathPattern{Path: "/openapi.json", Match: "exact"})

		resp, err := srv.Check(ctx, makeReq("/openapi.json", "Basic dXNlcjpwYXNz"))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code == 0 {
			t.Error("expected denial for unsupported auth scheme on optional path, got OK")
		}
	})

	t.Run("no optional auth configured preserves existing behavior", func(t *testing.T) {
		trustStore := trust.NewStubStore()
		trustStore.AddValidator(trust.NewStubValidator(trust.CredentialTypeBearer))
		dataSourceRegistry := service.NewDataSourceRegistry()
		issuerRegistry := service.NewSimpleRegistry()
		tokenService := service.NewTokenService("parsec.test", dataSourceRegistry, issuerRegistry, nil)

		srv := NewAuthzServer(trustStore, tokenService, nil, nil)

		resp, err := srv.Check(ctx, makeReq("/openapi.json", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code == 0 {
			t.Error("expected denial when no optional auth configured, got OK")
		}
	})

	t.Run("percent-encoded path traversal does not bypass optional auth", func(t *testing.T) {
		srv, _ := setup(t, request.PathPattern{Path: "/api/docs/", Match: "prefix"})

		bypassPaths := []string{
			"/api/docs/../secret",
			"/api/docs/%2e%2e/secret",
			"/api%2fdocs/secret",
			"/api/docs%2fsecret",
			"/api/docs/%2Fsecret",
		}
		for _, p := range bypassPaths {
			resp, err := srv.Check(ctx, makeReq(p, ""))
			if err != nil {
				t.Fatalf("path %q: unexpected error: %v", p, err)
			}
			if resp.Status.Code == 0 {
				t.Errorf("path %q: expected denial for traversal attempt, got OK", p)
			}
		}
	})

	t.Run("optional path with cookie but no authorization allows through until credential sources expand", func(t *testing.T) {
		// Until PR #125 credential_sources (e.g. cs_jwt cookie) are wired into
		// extractCredential, cookie-only requests report ErrNoCredential and
		// optional-auth pass-through applies the same as a bare request.
		srv, _ := setup(t, request.PathPattern{Path: "/openapi.json", Match: "exact"})

		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/openapi.json",
						Headers: map[string]string{
							"cookie": "cs_jwt=eyJhbGciOiJIUzI1NiJ9.test",
						},
					},
				},
			},
		}

		resp, err := srv.Check(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != 0 {
			t.Errorf("expected OK for optional path without bearer credential, got code %d: %s",
				resp.Status.Code, resp.Status.Message)
		}
	})

	t.Run("percent-encoded exact path does not bypass optional auth", func(t *testing.T) {
		srv, _ := setup(t, request.PathPattern{Path: "/openapi.json", Match: "exact"})

		bypassPaths := []string{
			"/openapi%2ejson",
			"/%6fpenapi.json",
			"/openapi.json%00extra",
		}
		for _, p := range bypassPaths {
			resp, err := srv.Check(ctx, makeReq(p, ""))
			if err != nil {
				t.Fatalf("path %q: unexpected error: %v", p, err)
			}
			if resp.Status.Code == 0 {
				t.Errorf("path %q: expected denial for encoded bypass attempt, got OK", p)
			}
		}
	})

	t.Run("canonicalized path still matches when encoding is benign", func(t *testing.T) {
		srv, _ := setup(t, request.PathPattern{Path: "/openapi.json", Match: "exact"})

		resp, err := srv.Check(ctx, makeReq("/openapi.json?version=2", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != 0 {
			t.Errorf("expected OK for path with query string, got code %d", resp.Status.Code)
		}
	})

	t.Run("regex optional path without credentials allows through", func(t *testing.T) {
		srv, _ := setup(t, request.PathPattern{
			Path:  `^/api/[^/]+/v[0-9]+(\.[0-9]+)?/openapi.json$`,
			Match: request.MatchRegex,
		})

		resp, err := srv.Check(ctx, makeReq("/api/insights/v1/openapi.json", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != 0 {
			t.Errorf("expected OK for regex optional path, got code %d: %s", resp.Status.Code, resp.Status.Message)
		}
	})

	t.Run("optional path pass-through is not blocked by ForActor filter errors", func(t *testing.T) {
		filteredStore, err := trust.NewFilteredStore(
			trust.WithValidatorFilter(erroringValidatorFilter{}),
			trust.WithObserver(trust.NoOpTrustObserver{}),
		)
		if err != nil {
			t.Fatalf("failed to create filtered store: %v", err)
		}
		filteredStore.AddValidator("bearer-validator", trust.NewStubValidator(trust.CredentialTypeBearer))

		dataSourceRegistry := service.NewDataSourceRegistry()
		issuerRegistry := service.NewSimpleRegistry()
		tokenService := service.NewTokenService("parsec.test", dataSourceRegistry, issuerRegistry, nil)

		matcher, err := request.NewPathMatcher([]request.PathPattern{
			{Path: "/openapi.json", Match: "exact"},
		})
		if err != nil {
			t.Fatalf("failed to create path matcher: %v", err)
		}

		srv := NewAuthzServer(filteredStore, tokenService, nil, nil,
			WithOptionalAuthPathMatcher(matcher))

		resp, err := srv.Check(ctx, makeReq("/openapi.json", ""))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != 0 {
			t.Errorf("expected OK for optional path pass-through despite ForActor error, got code %d: %s",
				resp.Status.Code, resp.Status.Message)
		}
	})

	t.Run("percent-encoded path does not bypass regex optional auth", func(t *testing.T) {
		srv, _ := setup(t, request.PathPattern{
			Path:  `^/api/[^/]+/v[0-9]+(\.[0-9]+)?/openapi.json$`,
			Match: request.MatchRegex,
		})

		bypassPaths := []string{
			"/api/insights%2fv1/openapi.json",
			"/api%2finsights/v1/openapi.json",
			"/api/insights/v1/openapi%2ejson",
		}
		for _, p := range bypassPaths {
			resp, err := srv.Check(ctx, makeReq(p, ""))
			if err != nil {
				t.Fatalf("path %q: unexpected error: %v", p, err)
			}
			if resp.Status.Code == 0 {
				t.Errorf("path %q: expected denial for encoded bypass attempt, got OK", p)
			}
		}
	})
}

func TestAuthzServer_OptionalAuth_Observability(t *testing.T) {
	ctx := context.Background()

	t.Run("optional auth pass-through calls probe correctly", func(t *testing.T) {
		fakeObs := service.NewFakeObserver(t)

		trustStore := trust.NewStubStore()
		dataSourceRegistry := service.NewDataSourceRegistry()
		issuerRegistry := service.NewSimpleRegistry()
		tokenService := service.NewTokenService("parsec.test", dataSourceRegistry, issuerRegistry, nil)

		matcher, _ := request.NewPathMatcher([]request.PathPattern{
			{Path: "/openapi.json", Match: "exact"},
		})
		srv := NewAuthzServer(trustStore, tokenService, nil, fakeObs,
			WithOptionalAuthPathMatcher(matcher))

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
			"SubjectCredentialExtractionFailed",
			"OptionalAuthPassThrough",
			"End",
		)
	})
}
