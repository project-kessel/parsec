package e2e_test

import (
	"context"
	"encoding/base64"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/server"
)

// IMPORTANT: registry auth flow is specific to Red Hat HCC deployment of parsec.
// These tests could be ripped out at any time should we refactor e2e tests to keep things generic.
//
// registryAuthSubtests runs the registry auth test cases against the given
// AuthzServer. Registry auth validates Basic Auth credentials of the form
// "org_id|username:password" against an external registry authorization service.
// The org_id prefix is optional — credentials like "|username:password" are valid
// and should produce a successful response with an empty org_id.
func registryAuthSubtests(t *testing.T, authzServer *server.AuthzServer) {
	t.Run("registry auth with org_id", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(), checkRequestWithBasicAuth("123|alice", "secret"))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)

		identity := decodeTokenIdentity(t, resp)

		if identity["auth_type"] != "registry-auth" {
			t.Errorf("expected auth_type 'registry-auth', got %v", identity["auth_type"])
		}
		if identity["org_id"] != "123" {
			t.Errorf("expected org_id '123', got %v", identity["org_id"])
		}

		user, ok := identity["user"].(map[string]any)
		if !ok {
			t.Fatalf("expected user to be a map, got %T", identity["user"])
		}
		if user["username"] != "alice" {
			t.Errorf("expected username 'alice', got %v", user["username"])
		}
	})

	t.Run("registry auth without org_id", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(), checkRequestWithBasicAuth("|alice", "secret"))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)

		identity := decodeTokenIdentity(t, resp)

		if identity["auth_type"] != "registry-auth" {
			t.Errorf("expected auth_type 'registry-auth', got %v", identity["auth_type"])
		}
		if identity["org_id"] != nil {
			t.Errorf("expected org_id nil, got %v", identity["org_id"])
		}

		user, ok := identity["user"].(map[string]any)
		if !ok {
			t.Fatalf("expected user to be a map, got %T", identity["user"])
		}
		if user["username"] != "alice" {
			t.Errorf("expected username 'alice', got %v", user["username"])
		}
	})

	t.Run("rejects missing pipe separator", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(), checkRequestWithBasicAuth("alice", "secret"))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedResponse(t, resp)
	})

	t.Run("rejects empty password", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(), checkRequestWithBasicAuth("|alice", ""))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedResponse(t, resp)
	})
}

func checkRequestWithBasicAuth(username, password string) *authv3.CheckRequest {
	cred := base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Path:   "/api/test",
					Headers: map[string]string{
						"authorization": "Basic " + cred,
					},
				},
			},
			Source: &authv3.AttributeContext_Peer{
				Address: &corev3.Address{
					Address: &corev3.Address_SocketAddress{
						SocketAddress: &corev3.SocketAddress{
							Address: "192.168.1.1",
						},
					},
				},
			},
		},
	}
}
