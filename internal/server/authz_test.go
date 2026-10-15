package server

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	typev3 "github.com/envoyproxy/go-control-plane/envoy/type/v3"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"

	"github.com/project-kessel/parsec/internal/issuer"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func mustParseCookies(t *testing.T, header string) []*http.Cookie {
	t.Helper()
	cookies, err := parseCookies(header)
	if err != nil {
		t.Fatalf("parseCookies(%q): %v", header, err)
	}
	return cookies
}

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

	authzServer := NewAuthzServer(trustStore, tokenService, nil, DefaultCredentialSources(), nil, nil, nil)

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
			t.Errorf("authorization header not in removal list: %v", okResp.HeadersToRemove)
		}
	})

	t.Run("missing authorization header returns Unauthenticated", func(t *testing.T) {
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

		if resp.Status.Code != int32(codes.Unauthenticated) {
			t.Errorf("expected Unauthenticated (%d), got %d: %s",
				codes.Unauthenticated, resp.Status.Code, resp.Status.Message)
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

func TestAuthzServer_WithActorFiltering(t *testing.T) {
	ctx := context.Background()

	// Setup filtered trust store with CEL-based filtering
	filteredStore, err := trust.NewFilteredStore(
		trust.WithCELFilter(`actor.trust_domain == "gateway.example.com" && validator_name in ["external-validator"]`),
		trust.WithObserver(trust.NoOpTrustObserver{}),
	)
	if err != nil {
		t.Fatalf("failed to create filtered store: %v", err)
	}

	// Add two validators - one for external tokens, one for internal tokens
	externalValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	externalValidator.WithResult(&trust.Result{
		Subject:     "external-user",
		Issuer:      "https://external-idp.com",
		TrustDomain: "external",
	})
	filteredStore.AddValidator("external-validator", externalValidator)

	internalValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	internalValidator.WithResult(&trust.Result{
		Subject:     "internal-user",
		Issuer:      "https://internal-idp.com",
		TrustDomain: "internal",
	})
	filteredStore.AddValidator("internal-validator", internalValidator)

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

	authzServer := NewAuthzServer(filteredStore, tokenService, nil, DefaultCredentialSources(), nil, nil, nil)

	t.Run("anonymous actor gets filtered store - no validators match", func(t *testing.T) {
		// No actor credentials in context, so ForActor will be called with AnonymousResult
		// The CEL filter requires trust_domain == "gateway.example.com", which won't match empty actor
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"authorization": "Bearer external-token",
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

		// Should deny - no validators available after filtering
		if resp.Status.Code == 0 {
			t.Error("expected denial for anonymous actor with no matching validators, got OK")
		}
	})

	t.Run("actor credentials via gRPC metadata - Bearer token", func(t *testing.T) {
		// Create a context with gRPC metadata containing actor credentials
		md := metadata.New(map[string]string{
			"authorization": "Bearer gateway-token",
		})
		actorCtx := metadata.NewIncomingContext(ctx, md)

		// Setup a validator for the gateway actor
		gatewayValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
		gatewayValidator.WithResult(&trust.Result{
			Subject:     "gateway-service",
			Issuer:      "https://gateway-idp.com",
			TrustDomain: "gateway.example.com",
		})

		// Create a new store with the gateway validator
		storeWithGateway, err := trust.NewFilteredStore(
			trust.WithCELFilter(`actor.trust_domain == "gateway.example.com" && validator_name in ["external-validator"]`),
			trust.WithObserver(trust.NoOpTrustObserver{}),
		)
		if err != nil {
			t.Fatalf("failed to create store: %v", err)
		}

		// Add gateway validator to validate actor
		storeWithGateway.AddValidator("gateway-validator", gatewayValidator)
		storeWithGateway.AddValidator("external-validator", externalValidator)
		storeWithGateway.AddValidator("internal-validator", internalValidator)

		authzServerWithGateway := NewAuthzServer(storeWithGateway, tokenService, nil, DefaultCredentialSources(), nil, nil, nil)

		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"authorization": "Bearer external-token",
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

		resp, err := authzServerWithGateway.Check(actorCtx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should succeed - gateway actor can access external-validator
		if resp.Status.Code != 0 {
			t.Errorf("expected OK for gateway actor with external validator, got code %d: %s",
				resp.Status.Code, resp.Status.Message)
		}

		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OK response, got nil")
		}
	})

	t.Run("actor validation failure returns Unauthenticated", func(t *testing.T) {
		// Create a store with only JWT validators - no Bearer validators
		// So when a Bearer actor token is presented, validation will fail
		emptyStore := trust.NewStubStore()

		// Add only a JWT validator for subjects, not Bearer
		jwtValidator := trust.NewStubValidator(trust.CredentialTypeJWT)
		jwtValidator.WithResult(&trust.Result{
			Subject:     "jwt-user",
			Issuer:      "https://jwt-idp.com",
			TrustDomain: "jwt",
		})
		emptyStore.AddValidator(jwtValidator)

		authzServerFailing := NewAuthzServer(emptyStore, tokenService, nil, DefaultCredentialSources(), nil, nil, nil)

		// Add actor credentials (Bearer) that will fail validation since no Bearer validator exists
		md := metadata.New(map[string]string{
			"authorization": "Bearer actor-token",
		})
		actorCtx := metadata.NewIncomingContext(ctx, md)

		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"authorization": "Bearer subject-token",
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

		resp, err := authzServerFailing.Check(actorCtx, req)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should deny with Unauthenticated - actor validation failed (no validator for Bearer type)
		if resp.Status.Code == 0 {
			t.Error("expected denial for invalid actor credentials, got OK")
		}

		if !strings.Contains(resp.Status.Message, "actor validation failed") {
			t.Errorf("expected 'actor validation failed' in message, got: %s", resp.Status.Message)
		}
	})
}

func TestAuthzServer_WithActorFilteringByRequestPath(t *testing.T) {
	ctx := context.Background()

	// Setup filtered trust store with CEL-based filtering that checks request path
	filteredStore, err := trust.NewFilteredStore(
		trust.WithCELFilter(`
			(validator_name == "admin-validator" && request.path.startsWith("/admin")) ||
			(validator_name == "user-validator" && request.path.startsWith("/api"))
		`),
		trust.WithObserver(trust.NoOpTrustObserver{}),
	)
	if err != nil {
		t.Fatalf("failed to create filtered store: %v", err)
	}

	adminValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	adminValidator.WithResult(&trust.Result{
		Subject:     "admin-user",
		Issuer:      "https://admin-idp.com",
		TrustDomain: "admin",
	})
	filteredStore.AddValidator("admin-validator", adminValidator)

	userValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	userValidator.WithResult(&trust.Result{
		Subject:     "regular-user",
		Issuer:      "https://user-idp.com",
		TrustDomain: "users",
	})
	filteredStore.AddValidator("user-validator", userValidator)

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

	authzServer := NewAuthzServer(filteredStore, tokenService, nil, DefaultCredentialSources(), nil, nil, nil)

	t.Run("admin path allows admin validator", func(t *testing.T) {
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/admin/dashboard",
						Headers: map[string]string{
							"authorization": "Bearer admin-token",
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

		// Should succeed - admin validator is available for /admin paths
		if resp.Status.Code != 0 {
			t.Errorf("expected OK for /admin path, got code %d: %s", resp.Status.Code, resp.Status.Message)
		}
	})

	t.Run("api path allows user validator", func(t *testing.T) {
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/users",
						Headers: map[string]string{
							"authorization": "Bearer user-token",
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

		// Should succeed - user validator is available for /api paths
		if resp.Status.Code != 0 {
			t.Errorf("expected OK for /api path, got code %d: %s", resp.Status.Code, resp.Status.Message)
		}
	})

	t.Run("wrong path denies access", func(t *testing.T) {
		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/other/resource",
						Headers: map[string]string{
							"authorization": "Bearer user-token",
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

		// Should deny - no validators match for /other paths
		if resp.Status.Code == 0 {
			t.Error("expected denial for /other path, got OK")
		}
	})
}

func TestAuthzServer_Check_Observability(t *testing.T) {
	ctx := context.Background()

	t.Run("successful authorization calls probe methods in correct order", func(t *testing.T) {
		// Setup
		fakeObs := service.NewFakeObserver(t)

		// Setup dependencies
		trustStore := trust.NewStubStore()
		stubValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
		trustStore.AddValidator(stubValidator)

		// Setup token service
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
		trustDomain := "parsec.test"
		tokenService := service.NewTokenService(trustDomain, dataSourceRegistry, issuerRegistry, nil)

		authzServer := NewAuthzServer(trustStore, tokenService, nil, DefaultCredentialSources(), nil, nil, fakeObs)

		// Configure stub validator to return success
		stubValidator.WithResult(&trust.Result{
			Subject:     "user-123",
			TrustDomain: trustDomain,
		})

		req := &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"authorization": "Bearer valid-token",
						},
					},
				},
			},
		}

		_, err := authzServer.Check(ctx, req)
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}

		// Verify observer saw probe with correct method sequence
		p := fakeObs.AssertSingleProbe("AuthzCheckStarted", nil)
		p.AssertProbeSequence(
			"RequestAttributesParsed",
			"ActorValidationSucceeded",
			"SubjectCredentialExtracted",
			"SubjectValidationSucceeded",
			"PolicyDecisionIssue",
			"RequestCompleted",
			"End",
		)
	})

	t.Run("authorization failure calls probe correctly", func(t *testing.T) {
		// Setup
		fakeObs := service.NewFakeObserver(t)

		trustStore := trust.NewStubStore()
		stubValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
		trustStore.AddValidator(stubValidator)

		dataSourceRegistry := service.NewDataSourceRegistry()
		issuerRegistry := service.NewSimpleRegistry()
		trustDomain := "parsec.test"
		tokenService := service.NewTokenService(trustDomain, dataSourceRegistry, issuerRegistry, nil)

		authzServer := NewAuthzServer(trustStore, tokenService, nil, DefaultCredentialSources(), nil, nil, fakeObs)

		// Create request with invalid token (not added to stubValidator)
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

		_, err := authzServer.Check(ctx, req)
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}

		// Verify observer saw probe with failure (StubValidator accepts any token)
		p := fakeObs.AssertSingleProbe("AuthzCheckStarted", nil)
		p.AssertProbeSequence(
			"RequestAttributesParsed",
			"ActorValidationSucceeded",
			"SubjectCredentialExtracted",
			"SubjectValidationSucceeded", // Still succeeds even for invalid token with StubValidator
			"PolicyDecisionIssue",
			"RequestCompleted",
			"End",
		)
	})

	t.Run("missing credentials triggers anonymous subject and policy denial", func(t *testing.T) {
		// With the authz check policy, missing credentials results in an
		// anonymous subject. The default StaticAuthenticatedPolicy denies
		// anonymous subjects. This should NOT fire
		// SubjectCredentialExtractionFailed (that's for malformed
		// credentials, not absent ones).
		fakeObs := service.NewFakeObserver(t)

		trustStore := trust.NewStubStore()
		dataSourceRegistry := service.NewDataSourceRegistry()
		issuerRegistry := service.NewSimpleRegistry()
		trustDomain := "parsec.test"
		tokenService := service.NewTokenService(trustDomain, dataSourceRegistry, issuerRegistry, nil)

		authzServer := NewAuthzServer(trustStore, tokenService, nil, DefaultCredentialSources(), nil, nil, fakeObs)

		// Create request with no authorization header
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
			t.Fatalf("Check failed: %v", err)
		}

		// Verify denial with Unauthenticated (anonymous subjects not allowed by default policy)
		if resp.Status.Code != int32(codes.Unauthenticated) {
			t.Errorf("expected Unauthenticated (%d), got %d: %s",
				codes.Unauthenticated, resp.Status.Code, resp.Status.Message)
		}

		p := fakeObs.AssertSingleProbe("AuthzCheckStarted", nil)
		p.AssertProbeSequence(
			"RequestAttributesParsed",
			"ActorValidationSucceeded",
			"SubjectAnonymous",
			"PolicyDecisionDeny",
			"RequestCompleted",
			"End",
		)
	})
}

func TestCredentialSanitizationHeaders(t *testing.T) {
	t.Run("rewrites cookie header when other cookies remain", func(t *testing.T) {
		ext := &CredentialExtraction{
			CookiesUsed: []string{"cs_jwt"},
		}

		headers, headersToRemove := removeCredentialPresentation(ext, mustParseCookies(t, "session=abc; cs_jwt=secret; theme=dark"))

		if len(headers) != 1 || headers[0].Header.Key != "cookie" {
			t.Fatalf("expected one cookie rewrite header, got %d headers", len(headers))
		}
		if headers[0].Header.Value != "session=abc; theme=dark" {
			t.Errorf("expected sanitized cookie %q, got %q",
				"session=abc; theme=dark", headers[0].Header.Value)
		}

		for _, name := range headersToRemove {
			if name == "cookie" {
				t.Error("cookie should not be in removal list when other cookies remain")
			}
		}
	})

	t.Run("removes entire cookie header when credential is the only cookie", func(t *testing.T) {
		ext := &CredentialExtraction{
			CookiesUsed: []string{"cs_jwt"},
		}

		headers, headersToRemove := removeCredentialPresentation(ext, mustParseCookies(t, "cs_jwt=secret"))

		if len(headers) != 0 {
			t.Errorf("expected no rewrite headers, got %d", len(headers))
		}

		found := false
		for _, name := range headersToRemove {
			if name == "cookie" {
				found = true
			}
		}
		if !found {
			t.Error("expected cookie in removal list when credential is the only cookie")
		}
	})

	t.Run("bearer headers used are returned for removal", func(t *testing.T) {
		ext := &CredentialExtraction{
			HeadersUsed: []string{"authorization"},
		}

		headers, headersToRemove := removeCredentialPresentation(ext, nil)

		if len(headers) != 0 {
			t.Errorf("expected no rewrite headers, got %d", len(headers))
		}
		if len(headersToRemove) != 1 || headersToRemove[0] != "authorization" {
			t.Errorf("expected [authorization] for removal, got %v", headersToRemove)
		}
	})

	t.Run("nil extraction returns nil", func(t *testing.T) {
		headers, headersToRemove := removeCredentialPresentation(nil, mustParseCookies(t, "some=cookies"))

		if headers != nil {
			t.Errorf("expected nil headers, got %v", headers)
		}
		if headersToRemove != nil {
			t.Errorf("expected nil headersToRemove, got %v", headersToRemove)
		}
	})

	t.Run("does not mutate the extraction HeadersUsed slice", func(t *testing.T) {
		ext := &CredentialExtraction{
			HeadersUsed: []string{"authorization"},
			CookiesUsed: []string{"cs_jwt"},
		}

		_, _ = removeCredentialPresentation(ext, mustParseCookies(t, "cs_jwt=secret"))

		if len(ext.HeadersUsed) != 1 || ext.HeadersUsed[0] != "authorization" {
			t.Errorf("HeadersUsed was mutated: %v", ext.HeadersUsed)
		}
	})
}

func TestSanitizeCookieHeader_roundTrip(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header string
		omit   []string
		want   string
	}{
		{
			name:   "JWT-like value with dots and base64url",
			header: "cred=remove-me; token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl",
			omit:   []string{"cred"},
			want:   "token=eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.c2lnbmF0dXJl",
		},
		{
			name:   "base64 padding with equals signs",
			header: "cred=remove-me; session=dGVzdA==",
			omit:   []string{"cred"},
			want:   "session=dGVzdA==",
		},
		{
			name:   "URL-encoded value",
			header: "cred=remove-me; redir=https%3A%2F%2Fexample.com%2Fpath%3Fq%3D1",
			omit:   []string{"cred"},
			want:   "redir=https%3A%2F%2Fexample.com%2Fpath%3Fq%3D1",
		},
		{
			name:   "value containing embedded equals",
			header: "cred=remove-me; data=key=val=ue",
			omit:   []string{"cred"},
			want:   "data=key=val=ue",
		},
		{
			name:   "empty value survives",
			header: "cred=remove-me; empty=",
			omit:   []string{"cred"},
			want:   "empty=",
		},
		{
			name:   "middle cookie omitted preserves neighbors",
			header: "before=aaa; cred=remove-me; after=zzz",
			omit:   []string{"cred"},
			want:   "before=aaa; after=zzz",
		},
		{
			name:   "special allowed characters in value",
			header: "cred=remove-me; prefs=!#$&'*+-.^`|~",
			omit:   []string{"cred"},
			want:   "prefs=!#$&'*+-.^`|~",
		},
		{
			name:   "multiple omitted cookies among multiple survivors",
			header: "a=1; cred1=x; b=2; cred2=y; c=3",
			omit:   []string{"cred1", "cred2"},
			want:   "a=1; b=2; c=3",
		},
		{
			name:   "case-sensitive match only omits exact name",
			header: "CS_JWT=upper; cs_jwt=lower; Cs_Jwt=mixed",
			omit:   []string{"cs_jwt"},
			want:   "CS_JWT=upper; Cs_Jwt=mixed",
		},
		{
			name:   "case-sensitive miss leaves all cookies intact",
			header: "Session=abc; TOKEN=xyz",
			omit:   []string{"session", "token"},
			want:   "Session=abc; TOKEN=xyz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := sanitizeCookieHeader(mustParseCookies(t, tt.header), tt.omit...)
			if got != tt.want {
				t.Errorf("round trip mismatch:\n  input: %q\n  got:   %q\n  want:  %q", tt.header, got, tt.want)
			}
		})
	}
}

func TestAuthzServer_Check_AllowWithoutIssue(t *testing.T) {
	ctx := context.Background()

	trustStore := trust.NewStubStore()
	stubValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	trustStore.AddValidator(stubValidator)

	// A policy that returns AllowWithoutIssue for authenticated subjects
	policy := &stubPolicy{decision: AuthzCheckDecision{
		Action: AuthzCheckAllowWithoutIssue,
		Reason: "allow without issue",
	}}

	authzServer := NewAuthzServer(trustStore, nil, policy, DefaultCredentialSources(), nil, nil, nil)

	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Path:   "/health",
					Headers: map[string]string{
						"authorization": "Bearer valid-token",
					},
				},
			},
		},
	}

	resp, err := authzServer.Check(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if resp.Status.Code != 0 {
		t.Errorf("expected OK, got code %d: %s", resp.Status.Code, resp.Status.Message)
	}

	okResp := resp.GetOkResponse()
	if okResp == nil {
		t.Fatal("expected OK response, got nil")
	}

	// Should still sanitize credential headers
	foundAuthRemoval := false
	for _, name := range okResp.HeadersToRemove {
		if name == "authorization" {
			foundAuthRemoval = true
		}
	}
	if !foundAuthRemoval {
		t.Errorf("expected authorization header removed even in AllowWithoutIssue, got %v", okResp.HeadersToRemove)
	}
}

func TestAuthzServer_Check_CookieSanitization(t *testing.T) {
	t.Parallel()

	trustStore := trust.NewStubStore()
	trustStore.AddValidator(trust.NewStubValidator(trust.CredentialTypeBearer))

	policy := &stubPolicy{decision: AuthzCheckDecision{
		Action: AuthzCheckAllowWithoutIssue,
		Reason: "allow",
	}}

	cookieSource := mustCookieSource(t, "cookie-jwt", "cs_jwt")
	authzServer := NewAuthzServer(trustStore, nil, policy, NewCredentialSources(cookieSource), nil, nil, nil)
	ctx := context.Background()

	t.Run("mixed-case Cookie header key is normalized and sanitized", func(t *testing.T) {
		t.Parallel()
		resp, err := authzServer.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api",
						Headers: map[string]string{
							"Cookie": "session=keep; cs_jwt=secret; theme=dark",
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatalf("expected OK response, got %v", resp.Status)
		}

		// The credential cookie should be stripped; other cookies should survive.
		var rewrittenCookie string
		for _, h := range okResp.Headers {
			if h.Header.Key == "cookie" {
				rewrittenCookie = h.Header.Value
			}
		}
		if rewrittenCookie != "session=keep; theme=dark" {
			t.Errorf("expected surviving cookies %q, got %q",
				"session=keep; theme=dark", rewrittenCookie)
		}

		for _, name := range okResp.HeadersToRemove {
			if name == "cookie" {
				t.Error("cookie header should be rewritten, not removed, when other cookies remain")
			}
		}
	})

	t.Run("only credential cookie removes entire header", func(t *testing.T) {
		t.Parallel()
		resp, err := authzServer.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api",
						Headers: map[string]string{
							"Cookie": "cs_jwt=secret",
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatalf("expected OK response, got %v", resp.Status)
		}

		for _, header := range okResp.Headers {
			if header.GetHeader().GetKey() == "cookie" {
				t.Errorf("expected no cookie rewrite header when all cookies consumed, got %v", okResp.Headers)
			}
		}

		found := false
		for _, name := range okResp.HeadersToRemove {
			if name == "cookie" {
				found = true
			}
		}
		if !found {
			t.Error("expected cookie in removal list when credential is the only cookie")
		}
	})

	t.Run("case mismatch in cookie name does not strip wrong cookie", func(t *testing.T) {
		t.Parallel()
		// Source is configured for "cs_jwt" but header has "CS_JWT" (different case).
		// Cookie names are case-sensitive per RFC 6265, so no credential should
		// be extracted and no sanitization should occur.
		noMatchServer := NewAuthzServer(trustStore, nil, nil, NewCredentialSources(cookieSource), nil, nil, nil)

		resp, err := noMatchServer.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api",
						Headers: map[string]string{
							"Cookie": "CS_JWT=secret; session=abc",
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// No credential extracted → default policy denies (unauthenticated)
		// or allows anonymously, depending on policy. Either way, the cookies
		// must NOT be touched.
		if okResp := resp.GetOkResponse(); okResp != nil {
			for _, h := range okResp.Headers {
				if h.Header.Key == "cookie" {
					t.Errorf("cookie header should not be rewritten when name case doesn't match, got %q", h.Header.Value)
				}
			}
			for _, name := range okResp.HeadersToRemove {
				if name == "cookie" {
					t.Error("cookie header should not be removed when name case doesn't match")
				}
			}
		}
	})
}

func TestAuthzServer_Check_NilHttpRequest(t *testing.T) {
	ctx := context.Background()

	authzServer := NewAuthzServer(trust.NewStubStore(), nil, nil, DefaultCredentialSources(), nil, nil, nil)

	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				// Http is nil
			},
		},
	}

	resp, err := authzServer.Check(ctx, req)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Should deny — nil HTTP request means credential context extraction fails
	if resp.Status.Code == 0 {
		t.Error("expected denial for nil HTTP request, got OK")
	}
}

func TestBuildRequestAttributes_NilHttp(t *testing.T) {
	srv := NewAuthzServer(nil, nil, nil, DefaultCredentialSources(), nil, nil, nil)

	req := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{},
		},
	}

	attrs := srv.buildRequestAttributes(req)
	if attrs.Method != "" {
		t.Errorf("expected empty method, got %q", attrs.Method)
	}
	if attrs.Path != "" {
		t.Errorf("expected empty path, got %q", attrs.Path)
	}
}

// stubPolicy is a simple AuthzCheckPolicy that returns a fixed decision.
type stubPolicy struct {
	decision AuthzCheckDecision
}

func (p *stubPolicy) Decide(_ context.Context, _ AuthzCheckPolicyInput) (AuthzCheckDecision, error) {
	return p.decision, nil
}

func TestAuthz_IssueResponse_MapperAbort(t *testing.T) {
	ctx := context.Background()

	newAuthzWithMapper := func(t *testing.T, script string, observer service.AuthzCheckObserver) *AuthzServer {
		t.Helper()
		celMapper, err := mapper.NewCELMapper(script)
		if err != nil {
			t.Fatalf("create mapper: %v", err)
		}
		trustStore := trust.NewStubStore()
		trustStore.AddValidator(trust.NewStubValidator(trust.CredentialTypeBearer))
		registry := service.NewSimpleRegistry()
		registry.Register(service.TokenTypeTransactionToken, issuer.NewStubIssuer(issuer.StubIssuerConfig{
			IssuerURL:                 "https://parsec.test",
			TTL:                       time.Minute,
			TransactionContextMappers: []service.ClaimMapper{celMapper},
		}))
		tokenService := service.NewTokenService("parsec.test", service.NewDataSourceRegistry(), registry, nil)
		return NewAuthzServer(trustStore, tokenService, nil, DefaultCredentialSources(), nil, nil, observer)
	}

	checkReq := &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Path:   "/api/resource",
					Headers: map[string]string{
						"authorization": "Bearer test-token",
					},
				},
			},
		},
	}

	t.Run("invalid_request_not_internal", func(t *testing.T) {
		observer := &capturingAuthzObserver{}
		srv := newAuthzWithMapper(t, `invalidSubject("impersonated tokens are not accepted")`, observer)
		resp, err := srv.Check(ctx, checkReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != int32(codes.InvalidArgument) {
			t.Errorf("code: got %d, want InvalidArgument (%d)", resp.Status.Code, codes.InvalidArgument)
		}
		if !strings.Contains(resp.Status.Message, "impersonated tokens are not accepted") {
			t.Errorf("message: got %q", resp.Status.Message)
		}
		denied := resp.GetDeniedResponse()
		if denied == nil {
			t.Fatal("expected DeniedHttpResponse")
		}
		if denied.GetStatus().GetCode() != typev3.StatusCode_BadRequest {
			t.Errorf("HTTP status: got %d, want BadRequest (%d)", denied.GetStatus().GetCode(), typev3.StatusCode_BadRequest)
		}
		if observer.completion.ReasonCode != "token_issuance_denied" {
			t.Errorf("audit reason: got %q, want token_issuance_denied", observer.completion.ReasonCode)
		}
		if len(observer.completion.TokenTypes) != 0 {
			t.Errorf("audit token types must be empty on denied issuance, got %v", observer.completion.TokenTypes)
		}
	})

	t.Run("fail_is_internal", func(t *testing.T) {
		observer := &capturingAuthzObserver{}
		srv := newAuthzWithMapper(t, `fail("mapping exploded")`, observer)
		resp, err := srv.Check(ctx, checkReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != int32(codes.Internal) {
			t.Errorf("code: got %d, want Internal (%d)", resp.Status.Code, codes.Internal)
		}
		denied := resp.GetDeniedResponse()
		if denied == nil {
			t.Fatal("expected DeniedHttpResponse")
		}
		if denied.GetStatus().GetCode() != typev3.StatusCode_InternalServerError {
			t.Errorf("HTTP status: got %d, want InternalServerError (%d)", denied.GetStatus().GetCode(), typev3.StatusCode_InternalServerError)
		}
		if observer.completion.ReasonCode != "token_issuance_failed" {
			t.Errorf("audit reason: got %q, want token_issuance_failed", observer.completion.ReasonCode)
		}
		if len(observer.completion.TokenTypes) != 0 {
			t.Errorf("audit token types must be empty on failed issuance, got %v", observer.completion.TokenTypes)
		}
	})

	t.Run("nil_token_is_internal", func(t *testing.T) {
		trustStore := trust.NewStubStore()
		trustStore.AddValidator(trust.NewStubValidator(trust.CredentialTypeBearer))
		registry := service.NewSimpleRegistry()
		registry.Register(service.TokenTypeTransactionToken, &nilTokenIssuer{})
		tokenService := service.NewTokenService("parsec.test", service.NewDataSourceRegistry(), registry, nil)
		observer := &capturingAuthzObserver{}
		srv := NewAuthzServer(trustStore, tokenService, nil, DefaultCredentialSources(), nil, nil, observer)

		resp, err := srv.Check(ctx, checkReq)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != int32(codes.Internal) {
			t.Errorf("code: got %d, want Internal (%d)", resp.Status.Code, codes.Internal)
		}
		if resp.Status.Code == int32(codes.OK) {
			t.Fatal("nil token must not return OK")
		}
		denied := resp.GetDeniedResponse()
		if denied == nil {
			t.Fatal("expected DeniedHttpResponse")
		}
		if denied.GetStatus().GetCode() != typev3.StatusCode_InternalServerError {
			t.Errorf("HTTP status: got %d, want InternalServerError (%d)", denied.GetStatus().GetCode(), typev3.StatusCode_InternalServerError)
		}
		if !strings.Contains(resp.Status.Message, "no token") {
			t.Errorf("message: got %q", resp.Status.Message)
		}
		if observer.completion.ReasonCode != "token_issuance_failed" {
			t.Errorf("audit reason: got %q, want token_issuance_failed", observer.completion.ReasonCode)
		}
		if len(observer.completion.TokenTypes) != 0 {
			t.Errorf("audit token types must be empty on failed issuance, got %v", observer.completion.TokenTypes)
		}
	})
}

// nilTokenIssuer returns a successful ExchangeResult with a nil Token — the
// programmer-error path that must fail closed at the transport layer.
type nilTokenIssuer struct{}

func (nilTokenIssuer) Issue(context.Context, *service.IssueContext) (service.ExchangeResult, error) {
	return service.ExchangeResult{}, nil
}

func (nilTokenIssuer) PublicKeys(context.Context) ([]service.PublicKey, error) {
	return nil, nil
}

func TestAuthz_DenialHTTPStatus(t *testing.T) {
	ctx := context.Background()

	t.Run("validation_unauthenticated_401", func(t *testing.T) {
		trustStore := trust.NewStubStore()
		v := trust.NewStubValidator(trust.CredentialTypeBearer)
		v.WithError(trust.ErrInvalidToken)
		trustStore.AddValidator(v)

		registry := service.NewSimpleRegistry()
		registry.Register(service.TokenTypeTransactionToken, issuer.NewStubIssuer(issuer.StubIssuerConfig{
			IssuerURL: "https://parsec.test",
			TTL:       time.Minute,
		}))
		tokenService := service.NewTokenService("parsec.test", service.NewDataSourceRegistry(), registry, nil)
		srv := NewAuthzServer(trustStore, tokenService, nil, DefaultCredentialSources(), nil, nil, nil)

		resp, err := srv.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method:  "GET",
						Path:    "/api/resource",
						Headers: map[string]string{"authorization": "Bearer bad"},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != int32(codes.Unauthenticated) {
			t.Errorf("code: got %d, want Unauthenticated", resp.Status.Code)
		}
		denied := resp.GetDeniedResponse()
		if denied == nil {
			t.Fatal("expected DeniedHttpResponse")
		}
		if denied.GetStatus() == nil {
			t.Fatal("DeniedHttpResponse.Status must be set (Envoy defaults unset to 403)")
		}
		if denied.GetStatus().GetCode() != typev3.StatusCode_Unauthorized {
			t.Errorf("HTTP status: got %d, want Unauthorized (401)", denied.GetStatus().GetCode())
		}
	})

	t.Run("policy_deny_403", func(t *testing.T) {
		trustStore := trust.NewStubStore()
		trustStore.AddValidator(trust.NewStubValidator(trust.CredentialTypeBearer))
		registry := service.NewSimpleRegistry()
		registry.Register(service.TokenTypeTransactionToken, issuer.NewStubIssuer(issuer.StubIssuerConfig{
			IssuerURL: "https://parsec.test",
			TTL:       time.Minute,
		}))
		tokenService := service.NewTokenService("parsec.test", service.NewDataSourceRegistry(), registry, nil)
		srv := NewAuthzServer(trustStore, tokenService, &stubPolicy{
			decision: AuthzCheckDecision{Action: AuthzCheckDeny, Reason: "not allowed"},
		}, DefaultCredentialSources(), nil, nil, nil)

		resp, err := srv.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method:  "GET",
						Path:    "/api/resource",
						Headers: map[string]string{"authorization": "Bearer test-token"},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resp.Status.Code != int32(codes.PermissionDenied) {
			t.Errorf("code: got %d, want PermissionDenied", resp.Status.Code)
		}
		denied := resp.GetDeniedResponse()
		if denied == nil {
			t.Fatal("expected DeniedHttpResponse")
		}
		if denied.GetStatus().GetCode() != typev3.StatusCode_Forbidden {
			t.Errorf("HTTP status: got %d, want Forbidden (403)", denied.GetStatus().GetCode())
		}
	})
}

func TestAuthzServer_DropHeaders(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	trustStore := trust.NewStubStore()
	stubValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	stubValidator.WithResult(&trust.Result{
		Subject:     "user-123",
		TrustDomain: "parsec.test",
	})
	trustStore.AddValidator(stubValidator)

	t.Run("drop headers removed on authenticated issue", func(t *testing.T) {
		t.Parallel()

		dataSourceRegistry := service.NewDataSourceRegistry()
		issuerRegistry := service.NewSimpleRegistry()
		issuerRegistry.Register(service.TokenTypeTransactionToken, issuer.NewStubIssuer(issuer.StubIssuerConfig{
			IssuerURL: "https://parsec.test",
			TTL:       time.Minute,
		}))
		tokenService := service.NewTokenService("parsec.test", dataSourceRegistry, issuerRegistry, nil)

		dropHeaders := []string{"x-rh-certauth-cn", "x-rh-certauth-issuer", "x-rh-insights-gateway-secret"}
		authzServer := NewAuthzServer(trustStore, tokenService, nil, DefaultCredentialSources(), dropHeaders, nil, nil)

		resp, err := authzServer.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"authorization":                "Bearer test-token",
							"x-rh-certauth-cn":             "/CN=spoofed",
							"x-rh-certauth-issuer":         "/O=Evil Corp",
							"x-rh-insights-gateway-secret": "fake-psk",
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OkResponse")
		}

		// authorization comes from HeadersUsed; the three drop_headers come from dropHeaders
		assertHeadersRemoved(t, okResp.HeadersToRemove,
			"authorization", "x-rh-certauth-cn", "x-rh-certauth-issuer", "x-rh-insights-gateway-secret")
	})

	t.Run("drop headers removed on anonymous allow without issue", func(t *testing.T) {
		t.Parallel()

		compiled, err := CompilePathPatterns([]string{"/api/.*/openapi\\.json"})
		if err != nil {
			t.Fatalf("CompilePathPatterns: %v", err)
		}
		policy := NewStaticAuthenticatedPolicy(nil, WithAllowAnonymousWithoutIssuePaths(compiled))

		dropHeaders := []string{"x-rh-certauth-cn", "x-rh-insights-env"}
		authzServer := NewAuthzServer(trust.NewStubStore(), nil, policy, DefaultCredentialSources(), dropHeaders, nil, nil)

		resp, err := authzServer.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/foo/openapi.json",
						Headers: map[string]string{
							"x-rh-certauth-cn":  "/CN=spoofed",
							"x-rh-insights-env": "prod",
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OkResponse for anonymous allowed path")
		}

		assertHeadersRemoved(t, okResp.HeadersToRemove, "x-rh-certauth-cn", "x-rh-insights-env")
	})

	t.Run("no drop headers preserves existing behavior", func(t *testing.T) {
		t.Parallel()

		policy := &stubPolicy{decision: AuthzCheckDecision{
			Action: AuthzCheckAllowWithoutIssue,
			Reason: "allow",
		}}
		authzServer := NewAuthzServer(trustStore, nil, policy, DefaultCredentialSources(), nil, nil, nil)

		resp, err := authzServer.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"authorization": "Bearer test-token",
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OkResponse")
		}

		assertHeadersRemoved(t, okResp.HeadersToRemove, "authorization")
		if len(okResp.HeadersToRemove) != 1 {
			t.Errorf("expected exactly 1 header removed, got %d: %v", len(okResp.HeadersToRemove), okResp.HeadersToRemove)
		}
	})

	t.Run("drop headers deduplicated with credential source headers", func(t *testing.T) {
		t.Parallel()

		certSource, err := NewForwardedClientCertCredentialSource("cert-auth", "x-rh-certauth-cn", "x-rh-certauth-issuer")
		if err != nil {
			t.Fatalf("NewForwardedClientCertCredentialSource: %v", err)
		}

		certValidator := trust.NewStubValidator(trust.CredentialTypeForwardedClientCert)
		certValidator.WithResult(&trust.Result{
			Subject:     "system-123",
			TrustDomain: "cert.redhat.com",
		})
		certStore := trust.NewStubStore()
		certStore.AddValidator(certValidator)

		policy := &stubPolicy{decision: AuthzCheckDecision{
			Action: AuthzCheckAllowWithoutIssue,
			Reason: "allow",
		}}

		// drop_headers includes x-rh-certauth-cn which the cert source already marks in HeadersUsed
		dropHeaders := []string{"x-rh-certauth-cn", "x-rh-certauth-issuer", "x-rh-insights-gateway-secret"}
		authzServer := NewAuthzServer(certStore, nil, policy, NewCredentialSources(certSource), dropHeaders, nil, nil)

		resp, err := authzServer.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"x-rh-certauth-cn":             "/CN=test-system-123",
							"x-rh-certauth-issuer":         "/C=US/O=Red Hat",
							"x-rh-insights-gateway-secret": "fake-psk",
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OkResponse")
		}

		assertHeadersRemoved(t, okResp.HeadersToRemove,
			"x-rh-certauth-cn", "x-rh-certauth-issuer", "x-rh-insights-gateway-secret")

		// Verify no duplicates
		seen := make(map[string]int, len(okResp.HeadersToRemove))
		for _, h := range okResp.HeadersToRemove {
			seen[h]++
		}
		for h, count := range seen {
			if count > 1 {
				t.Errorf("header %q appears %d times in HeadersToRemove (expected 1)", h, count)
			}
		}
	})

	t.Run("drop headers normalized to lowercase", func(t *testing.T) {
		t.Parallel()

		policy := &stubPolicy{decision: AuthzCheckDecision{
			Action: AuthzCheckAllowWithoutIssue,
			Reason: "allow",
		}}

		dropHeaders := []string{"X-RH-CertAuth-CN", "X-RH-Insights-Gateway-Secret"}
		authzServer := NewAuthzServer(trustStore, nil, policy, DefaultCredentialSources(), dropHeaders, nil, nil)

		resp, err := authzServer.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"authorization": "Bearer test-token",
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OkResponse")
		}

		assertHeadersRemoved(t, okResp.HeadersToRemove,
			"authorization", "x-rh-certauth-cn", "x-rh-insights-gateway-secret")
	})

	t.Run("deny response does not include drop headers", func(t *testing.T) {
		t.Parallel()

		policy := &stubPolicy{decision: AuthzCheckDecision{
			Action: AuthzCheckDeny,
			Reason: "not allowed",
		}}

		dropHeaders := []string{"x-rh-certauth-cn", "cs_jwt"}
		authzServer := NewAuthzServer(trustStore, nil, policy, DefaultCredentialSources(), dropHeaders, nil, nil)

		resp, err := authzServer.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"x-rh-certauth-cn": "/CN=spoofed",
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if resp.GetOkResponse() != nil {
			t.Fatal("expected denied response, got OkResponse")
		}
		deniedResp := resp.GetDeniedResponse()
		if deniedResp == nil {
			t.Fatal("expected DeniedResponse")
		}
		// Envoy rejects denied requests entirely, so drop_headers has nothing
		// to do here; the deny path must not call mergeDropHeaders.
	})

	t.Run("issued token header in drop_headers is not removed on Issue path", func(t *testing.T) {
		t.Parallel()

		dataSourceRegistry := service.NewDataSourceRegistry()
		issuerRegistry := service.NewSimpleRegistry()
		issuerRegistry.Register(service.TokenTypeTransactionToken, issuer.NewStubIssuer(issuer.StubIssuerConfig{
			IssuerURL: "https://parsec.test",
			TTL:       time.Minute,
		}))
		tokenService := service.NewTokenService("parsec.test", dataSourceRegistry, issuerRegistry, nil)

		// "transaction-token" (lowercase, normalized form) collides with the
		// default policy's issued header "Transaction-Token".
		dropHeaders := []string{"transaction-token", "x-rh-certauth-cn"}
		authzServer := NewAuthzServer(trustStore, tokenService, nil, DefaultCredentialSources(), dropHeaders, nil, nil)

		resp, err := authzServer.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"authorization":    "Bearer test-token",
							"x-rh-certauth-cn": "/CN=spoofed",
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OkResponse")
		}

		// The non-colliding entry is still removed...
		assertHeadersRemoved(t, okResp.HeadersToRemove, "authorization", "x-rh-certauth-cn")

		// ...but the issued token's header must NOT be in the removal list,
		// or Envoy would set it and then immediately delete it.
		for _, h := range okResp.HeadersToRemove {
			if h == "transaction-token" {
				t.Fatalf("transaction-token must not be in HeadersToRemove when it is also an issued header: %v", okResp.HeadersToRemove)
			}
		}

		// The issued token itself must be present in the response headers.
		found := false
		for _, h := range okResp.Headers {
			if h.GetHeader().GetKey() == "Transaction-Token" {
				found = true
				if h.GetHeader().GetValue() == "" {
					t.Error("issued Transaction-Token header has empty value")
				}
			}
		}
		if !found {
			t.Fatalf("expected issued Transaction-Token header in response, got %v", okResp.Headers)
		}
	})

	t.Run("client-supplied x-rh-identity stripped on anonymous allow-without-issue path", func(t *testing.T) {
		t.Parallel()

		compiled, err := CompilePathPatterns([]string{"/api/.*/openapi\\.json"})
		if err != nil {
			t.Fatalf("CompilePathPatterns: %v", err)
		}
		policy := NewStaticAuthenticatedPolicy(nil, WithAllowAnonymousWithoutIssuePaths(compiled))

		dropHeaders := []string{"x-rh-identity"}
		authzServer := NewAuthzServer(trust.NewStubStore(), nil, policy, DefaultCredentialSources(), dropHeaders, nil, nil)

		resp, err := authzServer.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/foo/openapi.json",
						Headers: map[string]string{
							"x-rh-identity": "spoofed-identity-envelope",
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OkResponse for anonymous allowed path")
		}

		// A client-supplied x-rh-identity must be stripped: no token is
		// issued on this path, so an unstripped value would be
		// indistinguishable from a parsec-issued identity to upstream.
		assertHeadersRemoved(t, okResp.HeadersToRemove, "x-rh-identity")
	})

	t.Run("cs_jwt cookie sanitized when bearer source matches instead", func(t *testing.T) {
		t.Parallel()

		bearerSource, err := NewBearerCredentialSource("bearer")
		if err != nil {
			t.Fatalf("NewBearerCredentialSource: %v", err)
		}
		cookieSource := mustCookieSource(t, "cookie-jwt", "cs_jwt")
		// Bearer is listed first, so it matches before the cookie source
		// when both credentials are present.
		credSources := NewCredentialSources(bearerSource, cookieSource)

		policy := &stubPolicy{decision: AuthzCheckDecision{
			Action: AuthzCheckAllowWithoutIssue,
			Reason: "allow",
		}}

		dropCookies := []string{"cs_jwt"}
		authzServer := NewAuthzServer(trustStore, nil, policy, credSources, nil, dropCookies, nil)

		resp, err := authzServer.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"authorization": "Bearer test-token",
							"cookie":        "cs_jwt=secret; session=abc",
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OkResponse")
		}

		// authorization is stripped via the matched bearer source's HeadersUsed.
		assertHeadersRemoved(t, okResp.HeadersToRemove, "authorization")

		// cs_jwt must not leak through the Cookie header, even though the
		// bearer source (not the cookie source) matched.
		var cookieValue string
		found := false
		for _, h := range okResp.Headers {
			if strings.EqualFold(h.GetHeader().GetKey(), "cookie") {
				found = true
				cookieValue = h.GetHeader().GetValue()
			}
		}
		if !found {
			t.Fatal("expected rewritten Cookie header in response")
		}
		if strings.Contains(cookieValue, "cs_jwt") {
			t.Errorf("cs_jwt cookie leaked through: Cookie=%q", cookieValue)
		}
		if !strings.Contains(cookieValue, "session=abc") {
			t.Errorf("expected session cookie to be preserved, got Cookie=%q", cookieValue)
		}
	})

	t.Run("entire cookie header removed when only drop_cookies cookie is present", func(t *testing.T) {
		t.Parallel()

		bearerSource, err := NewBearerCredentialSource("bearer")
		if err != nil {
			t.Fatalf("NewBearerCredentialSource: %v", err)
		}
		credSources := NewCredentialSources(bearerSource)

		policy := &stubPolicy{decision: AuthzCheckDecision{
			Action: AuthzCheckAllowWithoutIssue,
			Reason: "allow",
		}}

		dropCookies := []string{"cs_jwt"}
		authzServer := NewAuthzServer(trustStore, nil, policy, credSources, nil, dropCookies, nil)

		resp, err := authzServer.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"cookie": "cs_jwt=secret",
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OkResponse")
		}

		assertHeadersRemoved(t, okResp.HeadersToRemove, "cookie")
		for _, h := range okResp.Headers {
			if strings.EqualFold(h.GetHeader().GetKey(), "cookie") {
				t.Errorf("did not expect a Cookie rewrite when all cookies are dropped, got %q", h.GetHeader().GetValue())
			}
		}
	})

	t.Run("cookie in drop_headers removes entire cookie header even with drop_cookies", func(t *testing.T) {
		t.Parallel()

		bearerSource, err := NewBearerCredentialSource("bearer")
		if err != nil {
			t.Fatalf("NewBearerCredentialSource: %v", err)
		}
		credSources := NewCredentialSources(bearerSource)

		policy := &stubPolicy{decision: AuthzCheckDecision{
			Action: AuthzCheckAllowWithoutIssue,
			Reason: "allow",
		}}

		// Operator wants the entire Cookie header dropped AND has specific drop_cookies.
		// drop_headers "cookie" must win: no partial rewrite, just remove the header.
		dropHeaders := []string{"cookie", "x-rh-certauth-cn"}
		dropCookies := []string{"cs_jwt"}
		authzServer := NewAuthzServer(trustStore, nil, policy, credSources, dropHeaders, dropCookies, nil)

		resp, err := authzServer.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"authorization": "Bearer test-token",
							"cookie":        "cs_jwt=secret; session=abc",
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OkResponse")
		}

		// "cookie" must appear in the removal list (from drop_headers).
		assertHeadersRemoved(t, okResp.HeadersToRemove, "authorization", "cookie", "x-rh-certauth-cn")

		// No Cookie rewrite header should be present — the header is removed entirely.
		for _, h := range okResp.Headers {
			if strings.EqualFold(h.GetHeader().GetKey(), "cookie") {
				t.Errorf("did not expect a Cookie rewrite when cookie is in drop_headers, got %q", h.GetHeader().GetValue())
			}
		}
	})

	t.Run("cookie in drop_headers removes cookie rewrite from credential sanitization", func(t *testing.T) {
		t.Parallel()

		// Cookie source matches, producing a Cookie rewrite via removeCredentialPresentation.
		// drop_headers: ["cookie"] must override that rewrite.
		cookieSource := mustCookieSource(t, "cookie-jwt", "cs_jwt")
		credSources := NewCredentialSources(cookieSource)

		policy := &stubPolicy{decision: AuthzCheckDecision{
			Action: AuthzCheckAllowWithoutIssue,
			Reason: "allow",
		}}

		dropHeaders := []string{"cookie"}
		authzServer := NewAuthzServer(trustStore, nil, policy, credSources, dropHeaders, nil, nil)

		resp, err := authzServer.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method: "GET",
						Path:   "/api/resource",
						Headers: map[string]string{
							"cookie": "cs_jwt=test-token; other=keep",
						},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OkResponse")
		}

		assertHeadersRemoved(t, okResp.HeadersToRemove, "cookie")

		// No Cookie rewrite — the whole header is removed.
		for _, h := range okResp.Headers {
			if strings.EqualFold(h.GetHeader().GetKey(), "cookie") {
				t.Errorf("did not expect a Cookie rewrite when cookie is in drop_headers, got %q", h.GetHeader().GetValue())
			}
		}
	})

	t.Run("drop headers filters empty and whitespace entries", func(t *testing.T) {
		t.Parallel()

		policy := &stubPolicy{decision: AuthzCheckDecision{
			Action: AuthzCheckAllowWithoutIssue,
			Reason: "allow",
		}}

		dropHeaders := []string{"x-foo", "", "   ", "x-bar"}
		authzServer := NewAuthzServer(trustStore, nil, policy, DefaultCredentialSources(), dropHeaders, nil, nil)

		resp, err := authzServer.Check(ctx, &authv3.CheckRequest{
			Attributes: &authv3.AttributeContext{
				Request: &authv3.AttributeContext_Request{
					Http: &authv3.AttributeContext_HttpRequest{
						Method:  "GET",
						Path:    "/api/resource",
						Headers: map[string]string{},
					},
				},
			},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		okResp := resp.GetOkResponse()
		if okResp == nil {
			t.Fatal("expected OkResponse")
		}

		assertHeadersRemoved(t, okResp.HeadersToRemove, "x-foo", "x-bar")
		for _, h := range okResp.HeadersToRemove {
			if strings.TrimSpace(h) == "" {
				t.Errorf("blank entry leaked into HeadersToRemove: %v", okResp.HeadersToRemove)
			}
		}
		if len(okResp.HeadersToRemove) != 2 {
			t.Errorf("expected exactly 2 headers removed (blanks filtered), got %d: %v", len(okResp.HeadersToRemove), okResp.HeadersToRemove)
		}
	})
}

// assertHeadersRemoved verifies that all expected headers are present in the removal list.
func assertHeadersRemoved(t *testing.T, headersToRemove []string, expected ...string) {
	t.Helper()
	removed := make(map[string]bool, len(headersToRemove))
	for _, h := range headersToRemove {
		removed[h] = true
	}
	for _, h := range expected {
		if !removed[h] {
			t.Errorf("expected %q in HeadersToRemove, got %v", h, headersToRemove)
		}
	}
}
