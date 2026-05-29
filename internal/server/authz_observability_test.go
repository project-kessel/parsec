package server

import (
	"context"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/issuer"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

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

		authzServer := NewAuthzServer(trustStore, tokenService, nil, ScopePolicy{}, fakeObs)

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

		authzServer := NewAuthzServer(trustStore, tokenService, nil, ScopePolicy{}, fakeObs)

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

		authzServer := NewAuthzServer(trustStore, tokenService, nil, ScopePolicy{}, fakeObs)

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
