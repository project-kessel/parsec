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

	authzServer := NewAuthzServer(filteredStore, tokenService, nil, ScopePolicy{}, nil)

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

		authzServerWithGateway := NewAuthzServer(storeWithGateway, tokenService, nil, ScopePolicy{}, nil)

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

		authzServerFailing := NewAuthzServer(emptyStore, tokenService, nil, ScopePolicy{}, nil)

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

	authzServer := NewAuthzServer(filteredStore, tokenService, nil, ScopePolicy{}, nil)

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
