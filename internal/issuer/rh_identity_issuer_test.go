package issuer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestRHIdentityIssuer_Issue_Enrichment(t *testing.T) {
	t.Parallel()

	testMapper := service.NewStubClaimMapper(claims.Claims{
		"user": map[string]any{"user_id": "u1"},
		"internal": map[string]any{
			"org_id": "123",
		},
	})

	iss := NewRHIdentityIssuer(RHIdentityIssuerConfig{
		TokenType:    "urn:redhat:params:oauth:token-type:rh-identity",
		ClaimMappers: []service.ClaimMapper{testMapper},
		AuthType:     "jwt-auth",
	})

	tok, err := iss.Issue(context.Background(), &service.IssueContext{
		Subject:            &trust.Result{Subject: "s"},
		DataSourceRegistry: service.NewDataSourceRegistry(),
	})
	if err != nil {
		t.Fatalf("Issue: %v", err)
	}

	raw, err := base64.StdEncoding.DecodeString(tok.Value)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	id, _ := root["identity"].(map[string]any)
	if id == nil {
		t.Fatal("missing identity")
	}
	if id["auth_type"] != "jwt-auth" {
		t.Errorf("auth_type = %v", id["auth_type"])
	}
	internal, _ := id["internal"].(map[string]any)
	if internal == nil {
		t.Fatal("missing internal")
	}
	if internal["org_id"] != "123" {
		t.Errorf("org_id = %v", internal["org_id"])
	}
}
