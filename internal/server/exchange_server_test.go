package server

import (
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
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
