package e2e_test

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/codes"
)

// This file holds assertion and token-decoding helpers shared by all the
// hermetic authz flow tests. Each auth flow (registry, cert, JWT) keeps its own
// setup and subtests self-contained in its own file and relies on these helpers.

func assertOKResponse(t *testing.T, resp *authv3.CheckResponse) {
	t.Helper()
	if resp.Status.Code != int32(codes.OK) {
		t.Fatalf("expected OK response, got code %d: %s", resp.Status.Code, resp.Status.Message)
	}
}

func assertDeniedResponse(t *testing.T, resp *authv3.CheckResponse) {
	t.Helper()
	if resp.Status.Code == int32(codes.OK) {
		t.Fatal("expected denied response, got OK")
	}
}

func assertDeniedContains(t *testing.T, resp *authv3.CheckResponse, substr string) {
	t.Helper()
	assertDeniedResponse(t, resp)
	if !strings.Contains(resp.Status.Message, substr) {
		t.Errorf("expected deny message to contain %q, got %q", substr, resp.Status.Message)
	}
}

func decodeTokenIdentity(t *testing.T, resp *authv3.CheckResponse) map[string]any {
	t.Helper()

	okResp := resp.GetOkResponse()
	if okResp == nil {
		t.Fatal("expected OkResponse, got nil")
	}

	var tokenValue string
	for _, h := range okResp.Headers {
		if h.Header.Key == "Transaction-Token" {
			tokenValue = h.Header.Value
			break
		}
	}

	if tokenValue == "" {
		t.Fatal("Transaction-Token header not found in response")
	}

	tokenJSON, err := base64.StdEncoding.DecodeString(tokenValue)
	if err != nil {
		t.Fatalf("failed to base64-decode token: %v", err)
	}

	var claims map[string]any
	if err := json.Unmarshal(tokenJSON, &claims); err != nil {
		t.Fatalf("failed to parse token JSON: %v", err)
	}

	identity, ok := claims["identity"].(map[string]any)
	if !ok {
		t.Fatalf("expected 'identity' key in token claims, got keys: %v", mapKeys(claims))
	}

	return identity
}

func assertNestedMap(t *testing.T, parent map[string]any, key string) map[string]any {
	t.Helper()
	child, ok := parent[key].(map[string]any)
	if !ok {
		t.Fatalf("expected %s to be a map, got %T", key, parent[key])
	}
	return child
}

func mapKeys(m map[string]any) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return keys
}
