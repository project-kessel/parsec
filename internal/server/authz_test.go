package server

import (
	"context"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/issuer"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestAuthzServer_Check(t *testing.T) {
	ctx := context.Background()

	// Setup dependencies
	trustStore := trust.NewStubStore()

	stubValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	trustStore.AddValidator(stubValidator)

	// Setup token service
	dataSourceRegistry := service.NewDataSourceRegistry()

	issuerRegistry := service.NewSimpleRegistry()
	// Create mappers for the issuer
	txnMappers := []service.ClaimMapper{service.NewPassthroughSubjectMapper()}
	reqMappers := []service.ClaimMapper{service.NewRequestAttributesMapper()}
	txnTokenIssuer := issuer.NewStubIssuer(issuer.StubIssuerConfig{
		IssuerURL:                 "https://parsec.test",
		TTL:                       5 * time.Minute,
		TransactionContextMappers: txnMappers,
		RequestContextMappers:     reqMappers,
	})
	issuerRegistry.Register(service.TokenTypeTransactionToken, txnTokenIssuer)

	trustDomain := "parsec.test"
	tokenService := service.NewTokenService(trustDomain, dataSourceRegistry, issuerRegistry, nil)

	authzServer := NewAuthzServer(trustStore, tokenService, nil, ScopePolicy{}, nil)

	t.Run("successful authorization", func(t *testing.T) {
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"authorization": "Bearer test-token-123",
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

		resp, err := authzServer.Check(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Check status
		if resp.Status.Code != 0 { // 0 == OK
			t.Errorf("expected OK status, got code %d: %s", resp.Status.Code, resp.Status.Message)
		}

		// Check OK response
		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OK response, got nil")
		}

		// Check transaction token header is present
		foundToken := false
		for _, header := range okResp.Headers {
			if header.Header.Key == "Transaction-Token" {
				foundToken = true
				if header.Header.Value == "" {
					t.Error("transaction token value is empty")
				}
			}
		}
		if !foundToken {
			t.Error("transaction token header not found")
		}

		// Check that authorization header is removed
		if len(okResp.HeadersToRemove) == 0 {
			t.Error("expected headers to be removed, got none")
		}

		foundAuthRemoval := false
		for _, headerName := range okResp.HeadersToRemove {
			if headerName == "authorization" {
				foundAuthRemoval = true
			}
		}
		if !foundAuthRemoval {
			t.Errorf("authorization header not in removal list. Headers to remove: %v", okResp.HeadersToRemove)
		}
	})

	t.Run("missing authorization header", func(t *testing.T) {
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method:  "GET",
						Path:    "/api/resource",
						Headers: map[string]string{},
					},
				},
			},
		}

		resp, err := authzServer.Check(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should deny
		if resp.Status.Code == 0 {
			t.Error("expected denial, got OK")
		}

		deniedResp := resp.GetDeniedResponse()
		if deniedResp == nil {
			t.Fatal("expected denied response, got nil")
		}
	})

	t.Run("invalid bearer token", func(t *testing.T) {
		// Configure validator to reject
		stubValidator.WithError(trust.ErrInvalidToken)

		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"authorization": "Bearer invalid-token",
						},
					},
				},
			},
		}

		resp, err := authzServer.Check(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should deny
		if resp.Status.Code == 0 {
			t.Error("expected denial, got OK")
		}

		// Reset validator for other tests
		stubValidator.WithError(nil)
	})

	t.Run("successful authorization with context extensions", func(t *testing.T) {
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Host:   "api.example.com",
						Headers: map[string]string{
							"authorization": "Bearer test-token-123",
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
				// Envoy context extensions
				ContextExtensions: map[string]string{
					"env":       "production",
					"region":    "us-west-2",
					"namespace": "default",
					"cluster":   "prod-cluster-1",
				},
			},
		}

		resp, err := authzServer.Check(ctx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Check status - should succeed
		if resp.Status.Code != 0 { // 0 == OK
			t.Errorf("expected OK status, got code %d: %s", resp.Status.Code, resp.Status.Message)
		}

		// Verify token was issued
		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OK response, got nil")
		}

		foundToken := false
		for _, header := range okResp.Headers {
			if header.Header.Key == "Transaction-Token" {
				foundToken = true
				if header.Header.Value == "" {
					t.Error("transaction token value is empty")
				}
			}
		}
		if !foundToken {
			t.Error("transaction token header not found")
		}
	})

	t.Run("buildRequestAttributes extracts context extensions", func(t *testing.T) {
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "POST",
						Path:   "/api/users",
						Host:   "api.example.com",
						Headers: map[string]string{
							"content-type": "application/json",
						},
					},
				},
				Source: &authv3.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{
								Address: "10.0.1.5",
							},
						},
					},
				},
				ContextExtensions: map[string]string{
					"env":       "staging",
					"tenant_id": "tenant-123",
					"app":       "myapp",
				},
			},
		}

		attrs := authzServer.buildRequestAttributes(req)

		// Verify basic attributes
		if attrs.Method != "POST" {
			t.Errorf("expected method POST, got %s", attrs.Method)
		}

		if attrs.Path != "/api/users" {
			t.Errorf("expected path /api/users, got %s", attrs.Path)
		}

		if attrs.IPAddress != "10.0.1.5" {
			t.Errorf("expected IP 10.0.1.5, got %s", attrs.IPAddress)
		}

		// Verify host in Additional
		host, ok := attrs.Additional["host"].(string)
		if !ok || host != "api.example.com" {
			t.Errorf("expected host api.example.com in Additional, got %v", attrs.Additional["host"])
		}

		// Verify context extensions are in Additional
		contextExtensions, ok := attrs.Additional["context_extensions"].(map[string]string)
		if !ok {
			t.Fatalf("expected context_extensions in Additional as map[string]string, got %T", attrs.Additional["context_extensions"])
		}

		if contextExtensions["env"] != "staging" {
			t.Errorf("expected env=staging in context_extensions, got %s", contextExtensions["env"])
		}

		if contextExtensions["tenant_id"] != "tenant-123" {
			t.Errorf("expected tenant_id=tenant-123 in context_extensions, got %s", contextExtensions["tenant_id"])
		}

		if contextExtensions["app"] != "myapp" {
			t.Errorf("expected app=myapp in context_extensions, got %s", contextExtensions["app"])
		}
	})

	t.Run("buildRequestAttributes handles missing context extensions", func(t *testing.T) {
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/health",
						Host:   "api.example.com",
					},
				},
				Source: &authv3.AttributeContext_Peer{
					Address: &corev3.Address{
						Address: &corev3.Address_SocketAddress{
							SocketAddress: &corev3.SocketAddress{
								Address: "127.0.0.1",
							},
						},
					},
				},
				// No context extensions
			},
		}

		attrs := authzServer.buildRequestAttributes(req)

		// Should still have basic attributes
		if attrs.Method != "GET" {
			t.Errorf("expected method GET, got %s", attrs.Method)
		}

		// Additional should have host but not context_extensions
		if _, hasContextExt := attrs.Additional["context_extensions"]; hasContextExt {
			t.Error("expected no context_extensions when not provided by Envoy")
		}
	})

	t.Run("buildRequestAttributes with empty context extensions", func(t *testing.T) {
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api",
						Host:   "api.example.com",
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
				// Empty context extensions map
				ContextExtensions: map[string]string{},
			},
		}

		attrs := authzServer.buildRequestAttributes(req)

		// Should not include empty context_extensions
		if _, hasContextExt := attrs.Additional["context_extensions"]; hasContextExt {
			t.Error("expected no context_extensions when empty map provided")
		}
	})
}
