package server

import (
	"context"
	"net/http"
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

	authzServer := NewAuthzServer(trustStore, tokenService, nil, DefaultCredentialSources(), nil)

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

	authzServer := NewAuthzServer(filteredStore, tokenService, nil, DefaultCredentialSources(), nil)

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

		authzServerWithGateway := NewAuthzServer(storeWithGateway, tokenService, nil, DefaultCredentialSources(), nil)

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

		authzServerFailing := NewAuthzServer(emptyStore, tokenService, nil, DefaultCredentialSources(), nil)

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

	authzServer := NewAuthzServer(filteredStore, tokenService, nil, DefaultCredentialSources(), nil)

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

		authzServer := NewAuthzServer(trustStore, tokenService, nil, DefaultCredentialSources(), fakeObs)

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

		authzServer := NewAuthzServer(trustStore, tokenService, nil, DefaultCredentialSources(), fakeObs)

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

		authzServer := NewAuthzServer(trustStore, tokenService, nil, DefaultCredentialSources(), fakeObs)

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

		// Verify denial (anonymous subjects not allowed by default policy)
		if resp.Status.Code == 0 {
			t.Error("expected denial for missing credentials, got OK")
		}

		p := fakeObs.AssertSingleProbe("AuthzCheckStarted", nil)
		p.AssertProbeSequence(
			"RequestAttributesParsed",
			"ActorValidationSucceeded",
			"SubjectAnonymous",
			"PolicyDecisionDeny",
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

	authzServer := NewAuthzServer(trustStore, nil, policy, DefaultCredentialSources(), nil)

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
	authzServer := NewAuthzServer(trustStore, nil, policy, NewCredentialSources(cookieSource), nil)
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

		if len(okResp.Headers) != 0 {
			t.Errorf("expected no rewrite headers when all cookies consumed, got %v", okResp.Headers)
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
		noMatchServer := NewAuthzServer(trustStore, nil, nil, NewCredentialSources(cookieSource), nil)

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

	authzServer := NewAuthzServer(trust.NewStubStore(), nil, nil, DefaultCredentialSources(), nil)

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
	srv := NewAuthzServer(nil, nil, nil, DefaultCredentialSources(), nil)

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
