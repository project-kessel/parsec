package issuer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestUnsignedIssuer_Issue(t *testing.T) {
	tokenType := "urn:example:token-type:unsigned"

	// Create a mapper that returns test claims
	testMapper := service.NewStubClaimMapper(claims.Claims{
		"user_id":     "user-123",
		"department":  "engineering",
		"permissions": []string{"read", "write"},
		"level":       5,
	})
	issuer := NewUnsignedIssuer(UnsignedIssuerConfig{
		TokenType:    tokenType,
		ClaimMappers: []service.ClaimMapper{testMapper},
	})

	issueCtx := &service.IssueContext{
		Subject: &trust.Result{
			Subject: "test-subject",
		},
		Audience:           "test-audience",
		Scope:              mustOAuthScope(t, "test-scope"),
		DataSourceRegistry: service.NewDataSourceRegistry(),
	}

	// Issue the token
	token, err := issuer.Issue(context.Background(), issueCtx)
	if err != nil {
		t.Fatalf("Issue() failed: %v", err)
	}

	// Verify token is not empty
	if token.Value == "" {
		t.Error("Token value should not be empty")
	}

	// Verify token type is set correctly
	if token.Type != tokenType {
		t.Errorf("Expected token type %q, got %q", tokenType, token.Type)
	}

	// Verify token expires far in the future (year 9999)
	if token.ExpiresAt.Year() != 9999 {
		t.Errorf("Token should expire in year 9999, but ExpiresAt = %v", token.ExpiresAt)
	}

	// Verify IssuedAt is recent
	now := time.Now()
	if token.IssuedAt.After(now) || token.IssuedAt.Before(now.Add(-5*time.Second)) {
		t.Errorf("IssuedAt should be recent, got %v", token.IssuedAt)
	}

	// Decode the token value
	decodedJSON, err := base64.StdEncoding.DecodeString(token.Value)
	if err != nil {
		t.Fatalf("Failed to base64 decode token: %v", err)
	}

	// Unmarshal the JSON
	var decodedClaims claims.Claims
	if err := json.Unmarshal(decodedJSON, &decodedClaims); err != nil {
		t.Fatalf("Failed to unmarshal token JSON: %v", err)
	}

	// Verify the claims match the transaction context
	if decodedClaims["user_id"] != "user-123" {
		t.Errorf("Expected user_id=user-123, got %v", decodedClaims["user_id"])
	}
	if decodedClaims["department"] != "engineering" {
		t.Errorf("Expected department=engineering, got %v", decodedClaims["department"])
	}
	if decodedClaims["level"] != float64(5) { // JSON unmarshals numbers as float64
		t.Errorf("Expected level=5, got %v", decodedClaims["level"])
	}

	// Verify permissions array
	permissions, ok := decodedClaims["permissions"].([]interface{})
	if !ok {
		t.Fatalf("Expected permissions to be an array, got %T", decodedClaims["permissions"])
	}
	if len(permissions) != 2 {
		t.Errorf("Expected 2 permissions, got %d", len(permissions))
	}
	if permissions[0] != "read" || permissions[1] != "write" {
		t.Errorf("Expected permissions [read, write], got %v", permissions)
	}
}

func TestUnsignedIssuer_Issue_EmptyTransactionContext(t *testing.T) {
	// Create a mapper that returns empty claims
	testMapper := service.NewStubClaimMapper(claims.Claims{})
	issuer := NewUnsignedIssuer(UnsignedIssuerConfig{
		TokenType:    "test-token-type",
		ClaimMappers: []service.ClaimMapper{testMapper},
	})

	issueCtx := &service.IssueContext{
		Subject: &trust.Result{
			Subject: "test-subject",
		},
		Audience:           "test-audience",
		DataSourceRegistry: service.NewDataSourceRegistry(),
	}

	// Issue the token
	token, err := issuer.Issue(context.Background(), issueCtx)
	if err != nil {
		t.Fatalf("Issue() failed: %v", err)
	}

	// Decode the token value
	decodedJSON, err := base64.StdEncoding.DecodeString(token.Value)
	if err != nil {
		t.Fatalf("Failed to base64 decode token: %v", err)
	}

	// Unmarshal the JSON - should be an empty object
	var decodedClaims claims.Claims
	if err := json.Unmarshal(decodedJSON, &decodedClaims); err != nil {
		t.Fatalf("Failed to unmarshal token JSON: %v", err)
	}

	// Verify the claims are empty
	if len(decodedClaims) != 0 {
		t.Errorf("Expected empty claims, got %v", decodedClaims)
	}
}

func TestUnsignedIssuer_Issue_NilTransactionContext(t *testing.T) {
	// No mappers means nil claims
	issuer := NewUnsignedIssuer(UnsignedIssuerConfig{
		TokenType:    "test-token-type",
		ClaimMappers: []service.ClaimMapper{},
	})

	issueCtx := &service.IssueContext{
		Subject: &trust.Result{
			Subject: "test-subject",
		},
		Audience:           "test-audience",
		DataSourceRegistry: service.NewDataSourceRegistry(),
	}

	// Issue the token
	token, err := issuer.Issue(context.Background(), issueCtx)
	if err != nil {
		t.Fatalf("Issue() failed: %v", err)
	}

	// Decode the token value
	decodedJSON, err := base64.StdEncoding.DecodeString(token.Value)
	if err != nil {
		t.Fatalf("Failed to base64 decode token: %v", err)
	}

	// Should be empty object in JSON
	if string(decodedJSON) != "{}" {
		t.Errorf("Expected {}, got %s", string(decodedJSON))
	}
}

func TestUnsignedIssuer_Issue_MapperFailureDenied(t *testing.T) {
	celMapper, err := mapper.NewCELMapper(`false ? {"ok": true} : fail("unsupported_token_type")`)
	if err != nil {
		t.Fatalf("failed to create CEL mapper: %v", err)
	}

	iss := NewUnsignedIssuer(UnsignedIssuerConfig{
		TokenType:    "test-token-type",
		ClaimMappers: []service.ClaimMapper{celMapper},
	})

	issueCtx := &service.IssueContext{
		Subject: &trust.Result{
			Subject: "test-subject",
		},
		Audience:           "test-audience",
		DataSourceRegistry: service.NewDataSourceRegistry(),
	}

	token, issueErr := iss.Issue(context.Background(), issueCtx)
	if issueErr == nil {
		t.Fatal("expected Issue() to return error for mapper failure, got nil")
	}
	if token != nil {
		t.Errorf("expected nil token on error, got %v", token)
	}

	if !errors.Is(issueErr, service.ErrClaimMapping) {
		t.Fatalf("expected errors.Is(err, ErrClaimMapping), got: %v", issueErr)
	}

	var mappingErr *service.ClaimMappingError
	if !errors.As(issueErr, &mappingErr) {
		t.Fatalf("expected errors.As to unwrap ClaimMappingError, got: %T", issueErr)
	}
	if mappingErr.Message != "unsupported_token_type" {
		t.Errorf("expected message %q, got %q", "unsupported_token_type", mappingErr.Message)
	}
}

func TestUnsignedIssuer_PublicKeys(t *testing.T) {
	issuer := NewUnsignedIssuer(UnsignedIssuerConfig{
		TokenType:    "test-token-type",
		ClaimMappers: []service.ClaimMapper{},
	})

	keys, err := issuer.PublicKeys(context.Background())
	if err != nil {
		t.Fatalf("PublicKeys() failed: %v", err)
	}

	if len(keys) != 0 {
		t.Errorf("Expected no public keys for unsigned issuer, got %d", len(keys))
	}
}

func mustOAuthScope(t *testing.T, raw string) service.OAuthScope {
	t.Helper()
	scope, ok := service.NewOAuthScope(raw)
	if !ok {
		t.Fatalf("invalid oauth scope %q", raw)
	}
	return scope
}
