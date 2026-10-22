package server

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/issuer"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// TestTokenExchangeFormEncoded tests that the token exchange endpoint
// accepts application/x-www-form-urlencoded requests per RFC 8693.
func TestTokenExchangeFormEncoded(t *testing.T) {
	env := startTestServer(t, stubServerConfig())
	env.Srv.SetReady()

	formData := url.Values{}
	formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
	formData.Set("subject_token", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test")
	formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
	formData.Set("audience", "parsec.test")

	req, err := http.NewRequest(
		"POST",
		env.HTTPBaseURL+"/v1/token",
		strings.NewReader(formData.Encode()),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := env.HTTPClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", resp.StatusCode, body)
	}

	responseStr := string(body)
	if !strings.Contains(responseStr, "access_token") {
		t.Errorf("Response missing access_token field: %s", responseStr)
	}

	if !strings.Contains(responseStr, "token_type") {
		t.Errorf("Response missing token_type field: %s", responseStr)
	}
}

// TestTokenExchangeJSON tests that the endpoint still accepts JSON
// for clients that prefer gRPC-style requests.
func TestTokenExchangeJSON(t *testing.T) {
	env := startTestServer(t, stubServerConfig())
	env.Srv.SetReady()

	jsonData := `{
		"grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
		"subject_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
		"subject_token_type": "urn:ietf:params:oauth:token-type:jwt",
		"audience": "parsec.test"
	}`

	req, err := http.NewRequest(
		"POST",
		env.HTTPBaseURL+"/v1/token",
		strings.NewReader(jsonData),
	)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := env.HTTPClient.Do(req)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d. Body: %s", resp.StatusCode, body)
	}
}

// TestTokenExchangeErrorStatusCodes verifies that client errors return the
// correct HTTP status codes via grpc-gateway, not HTTP 500.
func TestTokenExchangeErrorStatusCodes(t *testing.T) {
	t.Run("unsupported_grant_type_400", func(t *testing.T) {
		env := startTestServer(t, stubServerConfig())
		env.Srv.SetReady()

		formData := url.Values{}
		formData.Set("grant_type", "client_credentials")
		formData.Set("subject_token", "some-token")

		code, body := postTokenExchange(t, env, formData)
		if code != http.StatusBadRequest {
			t.Errorf("expected 400 for unsupported grant_type, got %d. Body: %s", code, body)
		}
	})

	t.Run("missing_subject_token_401", func(t *testing.T) {
		env := startTestServer(t, stubServerConfig())
		env.Srv.SetReady()

		formData := url.Values{}
		formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
		// No subject_token: the stub validator will fail validation on empty credential

		code, body := postTokenExchange(t, env, formData)
		if code != http.StatusUnauthorized {
			t.Errorf("expected 401 for missing/invalid subject token, got %d. Body: %s", code, body)
		}
	})

	t.Run("invalid_request_context_400", func(t *testing.T) {
		env := startTestServer(t, stubServerConfig())
		env.Srv.SetReady()

		formData := url.Values{}
		formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
		formData.Set("subject_token", "valid-token")
		formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
		formData.Set("audience", "parsec.test")
		formData.Set("request_context", "not valid json at all")

		code, body := postTokenExchange(t, env, formData)
		if code != http.StatusBadRequest {
			t.Errorf("expected 400 for invalid request_context, got %d. Body: %s", code, body)
		}
	})

	t.Run("audience_mismatch_403", func(t *testing.T) {
		env := startTestServer(t, stubServerConfig())
		env.Srv.SetReady()

		formData := url.Values{}
		formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
		formData.Set("subject_token", "valid-token")
		formData.Set("subject_token_type", "urn:ietf:params:oauth:token-type:jwt")
		formData.Set("audience", "wrong.trust.domain")

		code, body := postTokenExchange(t, env, formData)
		if code != http.StatusForbidden {
			t.Errorf("expected 403 for audience mismatch, got %d. Body: %s", code, body)
		}
	})

	t.Run("actor_auth_failure_401", func(t *testing.T) {
		// Build a server whose trust store only has a JWT validator.
		// A Bearer actor credential (from gRPC metadata) will fail validation.
		trustStore := trust.NewStubStore()
		jwtOnly := trust.NewStubValidator(trust.CredentialTypeJWT)
		jwtOnly.WithResult(&trust.Result{Subject: "jwt-user", TrustDomain: "parsec.test"})
		trustStore.AddValidator(jwtOnly)

		issuerRegistry := service.NewSimpleRegistry()
		txnIssuer := issuer.NewStubIssuer(issuer.StubIssuerConfig{
			IssuerURL:                 "https://parsec.test",
			TTL:                       5 * time.Minute,
			TransactionContextMappers: []service.ClaimMapper{service.NewPassthroughSubjectMapper()},
			RequestContextMappers:     []service.ClaimMapper{service.NewRequestAttributesMapper()},
		})
		issuerRegistry.Register(service.TokenTypeTransactionToken, txnIssuer)
		tokenService := service.NewTokenService("parsec.test", service.NewDataSourceRegistry(), issuerRegistry, nil)

		cfg := Config{
			AuthzServer:    NewAuthzServer(trustStore, tokenService, nil, DefaultCredentialSources(), nil),
			ExchangeServer: NewExchangeServer(trustStore, tokenService, NewStubClaimsFilterRegistry(), DefaultCredentialSources(), nil),
			JWKSServer:     NewJWKSServer(JWKSServerConfig{IssuerRegistry: issuerRegistry, Observer: NoOpServerObserver{}}),
			Observer:       NoOpServerObserver{},
		}
		env := startTestServer(t, cfg)
		env.Srv.SetReady()

		formData := url.Values{}
		formData.Set("grant_type", "urn:ietf:params:oauth:grant-type:token-exchange")
		formData.Set("subject_token", "some-token")
		formData.Set("audience", "parsec.test")

		// Inject actor credential via the Authorization header on the HTTP request.
		// grpc-gateway forwards this as gRPC metadata.
		req, err := http.NewRequest("POST", env.HTTPBaseURL+"/v1/token",
			strings.NewReader(formData.Encode()))
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Authorization", "Bearer bad-actor-token")

		resp, err := env.HTTPClient.Do(req)
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		body, _ := io.ReadAll(resp.Body)
		if resp.StatusCode != http.StatusUnauthorized {
			t.Errorf("expected 401 for actor auth failure, got %d. Body: %s", resp.StatusCode, body)
		}
	})
}

// postTokenExchange is a helper that POSTs form-encoded data to /v1/token
// and returns the HTTP status code and body string.
func postTokenExchange(t *testing.T, env *testEnv, formData url.Values) (statusCode int, body string) {
	t.Helper()

	req, err := http.NewRequest("POST", env.HTTPBaseURL+"/v1/token",
		strings.NewReader(formData.Encode()))
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := env.HTTPClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}

	return resp.StatusCode, string(b)
}
