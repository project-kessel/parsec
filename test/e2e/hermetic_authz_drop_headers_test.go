package e2e_test

import (
	"context"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/issuer"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// TestHermeticAuthzCheckDropHeadersAndCookies demonstrates end-to-end testing
// of the authz_server.drop_headers and drop_cookies deny-lists via the
// ext_authz Authorization.Check RPC.
//
// This exercises, through the public API only:
//   - drop_headers removing a spoofed header alongside the credential
//     source's own HeadersUsed removal (x-rh-insights-gateway-secret)
//   - the Issue-path guard that excludes an issued token's header_name from
//     drop_headers so Envoy's set-before-remove mutation order does not
//     silently delete the token that was just issued (transaction-token)
//   - drop_cookies stripping a credential cookie (cs_jwt) that travels on an
//     unmatched channel alongside the cert-auth headers that did match
func TestHermeticAuthzCheckDropHeadersAndCookies(t *testing.T) {
	// ============================================================
	// 1. Build Components (no external I/O needed for this scenario)
	// ============================================================

	trustStore := trust.NewStubStore()
	certValidator := trust.NewStubValidator(trust.CredentialTypeForwardedClientCert)
	certValidator.WithResult(&trust.Result{
		Subject:     "system-123",
		TrustDomain: "cert.example.com",
	})
	trustStore.AddValidator(certValidator)

	issuerRegistry := service.NewSimpleRegistry()
	issuerRegistry.Register(service.TokenTypeTransactionToken, issuer.NewStubIssuer(issuer.StubIssuerConfig{
		IssuerURL: "https://parsec.test",
		TTL:       time.Minute,
	}))
	tokenService := service.NewTokenService("cert.example.com", service.NewDataSourceRegistry(), issuerRegistry, nil)

	certAuthSrc, err := server.NewForwardedClientCertCredentialSource("cert-auth", "x-rh-certauth-cn", "x-rh-certauth-issuer")
	if err != nil {
		t.Fatalf("failed to create forwarded client cert credential source: %v", err)
	}
	cookieSrc, err := server.NewCookieCredentialSource("cookie-jwt", "cs_jwt")
	if err != nil {
		t.Fatalf("failed to create cookie credential source: %v", err)
	}
	// cert-auth is listed first: when both cert headers and a cs_jwt cookie
	// are present, cert-auth matches and the cookie channel is left
	// unmatched -- exactly the scenario drop_cookies must still cover.
	credSources := server.NewCredentialSources(certAuthSrc, cookieSrc)

	policy := server.NewStaticAuthenticatedPolicy([]server.TokenTypeSpec{
		{Type: service.TokenTypeTransactionToken, HeaderName: "Transaction-Token"},
	})

	// "transaction-token" collides (case-insensitively) with the issued
	// token's header_name above; drop_headers must not delete it on Issue.
	dropHeaders := []string{"x-rh-insights-gateway-secret", "transaction-token"}
	dropCookies := []string{"cs_jwt"}

	// ============================================================
	// 2. Create the Authz Server
	// ============================================================

	authzServer := server.NewAuthzServer(trustStore, tokenService, policy, credSources, dropHeaders, dropCookies, nil, server.DefaultRequestIDConfig())

	// ============================================================
	// 3. Exercise the public Check() API
	// ============================================================

	resp, err := authzServer.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Path:   "/api/resource",
					Headers: map[string]string{
						"x-rh-certauth-cn":             "/CN=test-system-123",
						"x-rh-certauth-issuer":         "/C=US/O=Red Hat",
						"x-rh-insights-gateway-secret": "spoofed-psk",
						"cookie":                       "cs_jwt=secret; session=abc",
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Check RPC failed: %v", err)
	}

	okResp := resp.GetOkResponse()
	if okResp == nil {
		t.Fatalf("expected OkResponse, got %+v", resp)
	}

	// Credential-source-driven removal: cert headers consumed by the
	// matched source.
	assertContainsAll(t, okResp.HeadersToRemove, "x-rh-certauth-cn", "x-rh-certauth-issuer")

	// drop_headers removal: the spoofed gateway-secret header.
	assertContainsAll(t, okResp.HeadersToRemove, "x-rh-insights-gateway-secret")

	// Issue-path guard: the issued token's header must NOT be scheduled for
	// removal, even though "transaction-token" is in drop_headers.
	for _, h := range okResp.HeadersToRemove {
		if h == "transaction-token" {
			t.Fatalf("transaction-token must be excluded from HeadersToRemove on the Issue path, got %v", okResp.HeadersToRemove)
		}
	}

	// The issued token itself must reach the response.
	tokenValue := headerValue(okResp.Headers, "Transaction-Token")
	if tokenValue == "" {
		t.Fatalf("expected non-empty issued Transaction-Token header, got headers %v", okResp.Headers)
	}

	// drop_cookies: cs_jwt must be stripped from the Cookie header even
	// though the cert-auth source (not the cookie source) matched.
	cookieValue := headerValue(okResp.Headers, "cookie")
	if strings.Contains(cookieValue, "cs_jwt") {
		t.Errorf("cs_jwt cookie leaked through: Cookie=%q", cookieValue)
	}
	if !strings.Contains(cookieValue, "session=abc") {
		t.Errorf("expected session cookie preserved, got Cookie=%q", cookieValue)
	}
}

// assertContainsAll fails the test if any of expected is missing from values.
func assertContainsAll(t *testing.T, values []string, expected ...string) {
	t.Helper()
	set := make(map[string]bool, len(values))
	for _, v := range values {
		set[v] = true
	}
	for _, e := range expected {
		if !set[e] {
			t.Errorf("expected %q in %v", e, values)
		}
	}
}

// headerValue returns the value of the named header option (case-insensitive
// key match), or "" if not present.
func headerValue(headers []*corev3.HeaderValueOption, key string) string {
	for _, h := range headers {
		if strings.EqualFold(h.GetHeader().GetKey(), key) {
			return h.GetHeader().GetValue()
		}
	}
	return ""
}
