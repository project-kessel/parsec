package server

import (
	"context"
	"testing"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"

	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestAuthzServer_Check_AllowAnonymousPaths_AnonymousAllowed(t *testing.T) {
	t.Parallel()

	compiled, err := CompilePathPatterns([]string{
		`^/api/[^/]+/v[0-9]+(\.[0-9]+)?/openapi.json$`,
	})
	if err != nil {
		t.Fatalf("CompilePathPatterns: %v", err)
	}

	policy := NewStaticAuthenticatedPolicy(nil, WithAllowAnonymousWithoutIssuePaths(compiled))

	authzServer := NewAuthzServer(
		trust.NewStubStore(),
		service.NewTokenService("parsec.test", service.NewDataSourceRegistry(), service.NewSimpleRegistry(), nil),
		policy,
		DefaultCredentialSources(),
		nil,
	)

	resp, err := authzServer.Check(context.Background(), &authv3.CheckRequest{
		Attributes: &authv3.AttributeContext{
			Request: &authv3.AttributeContext_Request{
				Http: &authv3.AttributeContext_HttpRequest{
					Method: "GET",
					Path:   "/api/foo/v1/openapi.json",
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if resp.Status.Code != 0 {
		t.Fatalf("expected OK, got %d: %s", resp.Status.Code, resp.Status.Message)
	}
	if resp.GetOkResponse() == nil {
		t.Fatal("expected OK response")
	}
}
