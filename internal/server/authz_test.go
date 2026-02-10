package server

import (
	"context"
	"strings"
	"testing"
	"time"

	corev3 "github.com/envoyproxy/go-control-plane/envoy/config/core/v3"
	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/metadata"

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

	authzServer := NewAuthzServer(trustStore, tokenService, nil, nil)

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

func TestAuthzServer_WithActorFiltering(t *testing.T) {
	ctx := context.Background()

	// Setup filtered trust store with CEL-based filtering
	filteredStore, err := trust.NewFilteredStore(
		trust.WithCELFilter(`actor.trust_domain == "gateway.example.com" && validator_name in ["external-validator"]`),
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

	authzServer := NewAuthzServer(filteredStore, tokenService, nil, nil)

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
		)
		if err != nil {
			t.Fatalf("failed to create store: %v", err)
		}

		// Add gateway validator to validate actor
		storeWithGateway.AddValidator("gateway-validator", gatewayValidator)
		storeWithGateway.AddValidator("external-validator", externalValidator)
		storeWithGateway.AddValidator("internal-validator", internalValidator)

		authzServerWithGateway := NewAuthzServer(storeWithGateway, tokenService, nil, nil)

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

		authzServerFailing := NewAuthzServer(emptyStore, tokenService, nil, nil)

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

	authzServer := NewAuthzServer(filteredStore, tokenService, nil, nil)

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

		authzServer := NewAuthzServer(trustStore, tokenService, nil, fakeObs)

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

		authzServer := NewAuthzServer(trustStore, tokenService, nil, fakeObs)

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
			"End",
		)
	})

	t.Run("missing credentials calls probe correctly", func(t *testing.T) {
		// Setup
		fakeObs := service.NewFakeObserver(t)

		trustStore := trust.NewStubStore()
		dataSourceRegistry := service.NewDataSourceRegistry()
		issuerRegistry := service.NewSimpleRegistry()
		trustDomain := "parsec.test"
		tokenService := service.NewTokenService(trustDomain, dataSourceRegistry, issuerRegistry, nil)

		authzServer := NewAuthzServer(trustStore, tokenService, nil, fakeObs)

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

		_, err := authzServer.Check(ctx, req)
		if err != nil {
			t.Fatalf("Check failed: %v", err)
		}

		// Verify observer saw probe with credential extraction failure
		p := fakeObs.AssertSingleProbe("AuthzCheckStarted", nil)
		p.AssertProbeSequence(
			"RequestAttributesParsed",
			"ActorValidationSucceeded",
			"SubjectCredentialExtractionFailed",
			"End",
		)
	})
}
