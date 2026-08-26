package e2e_test

import (
	"context"
	"testing"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/server"
)

// certAuthSubtests runs cert-auth test cases against the given AuthzServer.
// Cert auth validates certificate credentials forwarded as x-rh-certauth-cn
// and x-rh-certauth-issuer headers by a TLS-terminating proxy.
func certAuthSubtests(t *testing.T, authzServer *server.AuthzServer) {
	t.Run("cert auth with simple CN", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(),
			checkRequestWithCertAuth("/CN=test-system-123", "CN=Red Hat CA"))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)

		identity := decodeTokenIdentity(t, resp)

		if identity["auth_type"] != "cert-auth" {
			t.Errorf("expected auth_type 'cert-auth', got %v", identity["auth_type"])
		}
		if identity["type"] != "System" {
			t.Errorf("expected type 'System', got %v", identity["type"])
		}
		if identity["org_id"] != "org-abc" {
			t.Errorf("expected org_id 'org-abc', got %v", identity["org_id"])
		}
		if identity["account_number"] != "12345" {
			t.Errorf("expected account_number '12345', got %v", identity["account_number"])
		}

		system := assertNestedMap(t, identity, "system")
		if system["cn"] != "test-system-123" {
			t.Errorf("expected system.cn 'test-system-123', got %v", system["cn"])
		}
		if system["cert_type"] != "satellite" {
			t.Errorf("expected system.cert_type 'satellite', got %v", system["cert_type"])
		}
	})

	t.Run("cert auth with compound subject", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(),
			checkRequestWithCertAuth("/O=MyOrg/CN=compound-cn/I=issuer", "CN=Some Issuer"))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertOKResponse(t, resp)

		identity := decodeTokenIdentity(t, resp)

		system := assertNestedMap(t, identity, "system")
		if system["cn"] != "compound-cn" {
			t.Errorf("expected system.cn 'compound-cn', got %v", system["cn"])
		}
	})

	t.Run("rejects BOP response without user object", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(),
			checkRequestWithCertAuth("/CN=no-user-field", "CN=Red Hat CA"))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedResponse(t, resp)
	})

	t.Run("rejects missing cn header", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(),
			checkRequestWithHeaders(map[string]string{
				"x-rh-certauth-issuer": "CN=Some Issuer",
			}))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedResponse(t, resp)
	})

	t.Run("rejects missing issuer header", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(),
			checkRequestWithHeaders(map[string]string{
				"x-rh-certauth-cn": "/CN=test",
			}))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedResponse(t, resp)
	})

	t.Run("no cert headers returns denied", func(t *testing.T) {
		resp, err := authzServer.Check(context.Background(),
			checkRequestWithHeaders(map[string]string{}))
		if err != nil {
			t.Fatalf("Check RPC failed: %v", err)
		}

		assertDeniedResponse(t, resp)
	})
}

func checkRequestWithCertAuth(cn, issuer string) *authv3.CheckRequest {
	return checkRequestWithHeaders(map[string]string{
		"x-rh-certauth-cn":     cn,
		"x-rh-certauth-issuer": issuer,
	})
}

func checkRequestWithHeaders(headers map[string]string) *authv3.CheckRequest {
	return &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method:  "GET",
					Path:    "/api/test",
					Headers: headers,
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
