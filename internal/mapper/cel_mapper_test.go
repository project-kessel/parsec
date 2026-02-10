package mapper

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// mockDataSource is a simple mock data source for testing
type mockDataSource struct {
	name string
	data any
}

func (m *mockDataSource) Name() string {
	return m.name
}

func (m *mockDataSource) Fetch(ctx context.Context, input *service.DataSourceInput) (*service.DataSourceResult, error) {
	data, err := json.Marshal(m.data)
	if err != nil {
		return nil, err
	}

	return &service.DataSourceResult{
		Data:        data,
		ContentType: service.ContentTypeJSON,
	}, nil
}

// mockCountingDataSource counts how many times Fetch is called
type mockCountingDataSource struct {
	name      string
	callCount int
}

func (m *mockCountingDataSource) Name() string {
	return m.name
}

func (m *mockCountingDataSource) Fetch(ctx context.Context, input *service.DataSourceInput) (*service.DataSourceResult, error) {
	m.callCount++
	data := map[string]any{"value": m.callCount}
	dataBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	return &service.DataSourceResult{
		Data:        dataBytes,
		ContentType: service.ContentTypeJSON,
	}, nil
}

func TestNewCELMapper(t *testing.T) {
	t.Run("creates mapper successfully with valid script", func(t *testing.T) {
		script := `{"user": "test"}`
		mapper, err := NewCELMapper(script)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if mapper == nil {
			t.Fatal("expected mapper, got nil")
		}

		if mapper.Script() != script {
			t.Errorf("expected script %s, got %s", script, mapper.Script())
		}
	})

	t.Run("fails with empty script", func(t *testing.T) {
		_, err := NewCELMapper("")
		if err == nil {
			t.Fatal("expected error for empty script")
		}
	})

	t.Run("fails with invalid CEL syntax", func(t *testing.T) {
		_, err := NewCELMapper("this is not valid CEL {{{")
		if err == nil {
			t.Fatal("expected error for invalid CEL syntax")
		}
	})
}

func TestCELMapper_Map(t *testing.T) {
	ctx := context.Background()

	t.Run("simple static map", func(t *testing.T) {
		mapper, err := NewCELMapper(`{"user": "alice", "role": "admin"}`)
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		input := &service.MapperInput{}
		result, err := mapper.Map(ctx, input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result == nil {
			t.Fatal("expected claims, got nil")
		}

		if result["user"] != "alice" {
			t.Errorf("expected user=alice, got %v", result["user"])
		}

		if result["role"] != "admin" {
			t.Errorf("expected role=admin, got %v", result["role"])
		}
	})

	t.Run("access subject", func(t *testing.T) {
		mapper, err := NewCELMapper(`{
			"user": subject.subject,
			"issuer": subject.issuer,
			"trust_domain": subject.trust_domain
		}`)
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		input := &service.MapperInput{
			Subject: &trust.Result{
				Subject:     "user@example.com",
				Issuer:      "https://idp.example.com",
				TrustDomain: "example-domain",
				ExpiresAt:   time.Now().Add(time.Hour),
				IssuedAt:    time.Now(),
			},
		}

		result, err := mapper.Map(ctx, input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result["user"] != "user@example.com" {
			t.Errorf("expected user=user@example.com, got %v", result["user"])
		}

		if result["issuer"] != "https://idp.example.com" {
			t.Errorf("expected issuer=https://idp.example.com, got %v", result["issuer"])
		}

		if result["trust_domain"] != "example-domain" {
			t.Errorf("expected trust_domain=example-domain, got %v", result["trust_domain"])
		}
	})

	t.Run("access subject claims", func(t *testing.T) {
		mapper, err := NewCELMapper(`{
			"email": subject.claims.email,
			"groups": subject.claims.groups
		}`)
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		input := &service.MapperInput{
			Subject: &trust.Result{
				Subject:     "user@example.com",
				Issuer:      "https://idp.example.com",
				TrustDomain: "example-domain",
				Claims: claims.Claims{
					"email":  "alice@example.com",
					"groups": []any{"admins", "users"},
				},
				ExpiresAt: time.Now().Add(time.Hour),
				IssuedAt:  time.Now(),
			},
		}

		result, err := mapper.Map(ctx, input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result["email"] != "alice@example.com" {
			t.Errorf("expected email=alice@example.com, got %v", result["email"])
		}

		groups, ok := result["groups"].([]any)
		if !ok {
			t.Fatalf("expected groups to be array, got %T", result["groups"])
		}

		if len(groups) != 2 {
			t.Errorf("expected 2 groups, got %d", len(groups))
		}
	})

	t.Run("access actor", func(t *testing.T) {
		mapper, err := NewCELMapper(`{
			"actor_id": actor.subject,
			"actor_trust_domain": actor.trust_domain
		}`)
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		input := &service.MapperInput{
			Actor: &trust.Result{
				Subject:     "spiffe://example.com/service/api",
				Issuer:      "https://spiffe.example.com",
				TrustDomain: "spiffe-domain",
				ExpiresAt:   time.Now().Add(time.Hour),
				IssuedAt:    time.Now(),
			},
		}

		result, err := mapper.Map(ctx, input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result["actor_id"] != "spiffe://example.com/service/api" {
			t.Errorf("expected actor_id=spiffe://example.com/service/api, got %v", result["actor_id"])
		}

		if result["actor_trust_domain"] != "spiffe-domain" {
			t.Errorf("expected actor_trust_domain=spiffe-domain, got %v", result["actor_trust_domain"])
		}
	})

	t.Run("access request attributes", func(t *testing.T) {
		mapper, err := NewCELMapper(`{
			"method": request.method,
			"path": request.path,
			"ip": request.ip_address,
			"user_agent": request.user_agent
		}`)
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		input := &service.MapperInput{
			RequestAttributes: &request.RequestAttributes{
				Method:    "POST",
				Path:      "/api/resource",
				IPAddress: "192.168.1.1",
				UserAgent: "test-client/1.0",
			},
		}

		result, err := mapper.Map(ctx, input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result["method"] != "POST" {
			t.Errorf("expected method=POST, got %v", result["method"])
		}

		if result["path"] != "/api/resource" {
			t.Errorf("expected path=/api/resource, got %v", result["path"])
		}

		if result["ip"] != "192.168.1.1" {
			t.Errorf("expected ip=192.168.1.1, got %v", result["ip"])
		}

		if result["user_agent"] != "test-client/1.0" {
			t.Errorf("expected user_agent=test-client/1.0, got %v", result["user_agent"])
		}
	})

	t.Run("access datasource", func(t *testing.T) {
		mapper, err := NewCELMapper(`{
			"roles": datasource("user_roles").roles,
			"region": datasource("geo").region
		}`)
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		registry := service.NewDataSourceRegistry()
		registry.Register(&mockDataSource{
			name: "user_roles",
			data: map[string]any{
				"roles": []string{"admin", "user"},
			},
		})
		registry.Register(&mockDataSource{
			name: "geo",
			data: map[string]any{
				"region": "us-west-2",
			},
		})

		input := &service.MapperInput{
			DataSourceRegistry: registry,
			DataSourceInput:    &service.DataSourceInput{},
		}

		result, err := mapper.Map(ctx, input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		roles, ok := result["roles"].([]any)
		if !ok {
			t.Fatalf("expected roles to be array, got %T", result["roles"])
		}

		if len(roles) != 2 {
			t.Errorf("expected 2 roles, got %d", len(roles))
		}

		if result["region"] != "us-west-2" {
			t.Errorf("expected region=us-west-2, got %v", result["region"])
		}
	})

	t.Run("conditional logic", func(t *testing.T) {
		mapper, err := NewCELMapper(`
			subject.trust_domain == "prod" 
				? {"env": "production", "level": "high"} 
				: {"env": "dev", "level": "low"}
		`)
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		// Test production case
		prodInput := &service.MapperInput{
			Subject: &trust.Result{
				Subject:     "user@example.com",
				Issuer:      "https://idp.example.com",
				TrustDomain: "prod",
				ExpiresAt:   time.Now().Add(time.Hour),
				IssuedAt:    time.Now(),
			},
		}

		result, err := mapper.Map(ctx, prodInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result["env"] != "production" {
			t.Errorf("expected env=production, got %v", result["env"])
		}

		if result["level"] != "high" {
			t.Errorf("expected level=high, got %v", result["level"])
		}

		// Test dev case
		devInput := &service.MapperInput{
			Subject: &trust.Result{
				Subject:     "user@example.com",
				Issuer:      "https://idp.example.com",
				TrustDomain: "dev",
				ExpiresAt:   time.Now().Add(time.Hour),
				IssuedAt:    time.Now(),
			},
		}

		result, err = mapper.Map(ctx, devInput)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result["env"] != "dev" {
			t.Errorf("expected env=dev, got %v", result["env"])
		}

		if result["level"] != "low" {
			t.Errorf("expected level=low, got %v", result["level"])
		}
	})

	t.Run("complex expression with multiple sources", func(t *testing.T) {
		mapper, err := NewCELMapper(`{
			"user": subject.subject,
			"issuer": subject.issuer,
			"ip": request.ip_address,
			"method": request.method,
			"roles": datasource("user_roles").roles,
			"computed": subject.subject + "@" + request.ip_address
		}`)
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		registry := service.NewDataSourceRegistry()
		registry.Register(&mockDataSource{
			name: "user_roles",
			data: map[string]any{
				"roles": []string{"admin"},
			},
		})

		input := &service.MapperInput{
			Subject: &trust.Result{
				Subject:     "alice",
				Issuer:      "https://idp.example.com",
				TrustDomain: "example-domain",
				ExpiresAt:   time.Now().Add(time.Hour),
				IssuedAt:    time.Now(),
			},
			RequestAttributes: &request.RequestAttributes{
				Method:    "GET",
				Path:      "/api/resource",
				IPAddress: "10.0.0.1",
			},
			DataSourceRegistry: registry,
			DataSourceInput:    &service.DataSourceInput{},
		}

		result, err := mapper.Map(ctx, input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result["user"] != "alice" {
			t.Errorf("expected user=alice, got %v", result["user"])
		}

		if result["ip"] != "10.0.0.1" {
			t.Errorf("expected ip=10.0.0.1, got %v", result["ip"])
		}

		if result["method"] != "GET" {
			t.Errorf("expected method=GET, got %v", result["method"])
		}

		if result["computed"] != "alice@10.0.0.1" {
			t.Errorf("expected computed=alice@10.0.0.1, got %v", result["computed"])
		}
	})

	t.Run("handles nil input gracefully", func(t *testing.T) {
		mapper, err := NewCELMapper(`{
			"has_subject": subject != null,
			"has_actor": actor != null,
			"has_request": request != null
		}`)
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		input := &service.MapperInput{
			// All fields nil
		}

		result, err := mapper.Map(ctx, input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result["has_subject"] != false {
			t.Errorf("expected has_subject=false, got %v", result["has_subject"])
		}

		if result["has_actor"] != false {
			t.Errorf("expected has_actor=false, got %v", result["has_actor"])
		}

		if result["has_request"] != false {
			t.Errorf("expected has_request=false, got %v", result["has_request"])
		}
	})

	t.Run("datasource caching", func(t *testing.T) {
		countingDS := &mockCountingDataSource{
			name: "counter",
		}

		mapper, err := NewCELMapper(`{
			"first": datasource("counter").value,
			"second": datasource("counter").value
		}`)
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		registry := service.NewDataSourceRegistry()
		registry.Register(countingDS)

		input := &service.MapperInput{
			DataSourceRegistry: registry,
			DataSourceInput:    &service.DataSourceInput{},
		}

		result, err := mapper.Map(ctx, input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Both should have the same value since the second call should be cached
		if result["first"] != result["second"] {
			t.Errorf("expected cached values to match, got first=%v, second=%v",
				result["first"], result["second"])
		}

		// Datasource should only be called once due to caching
		if countingDS.callCount != 1 {
			t.Errorf("expected datasource to be called once, got %d calls", countingDS.callCount)
		}
	})

	t.Run("returns error if mapper input is nil", func(t *testing.T) {
		mapper, err := NewCELMapper(`{"test": "value"}`)
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		_, err = mapper.Map(ctx, nil)
		if err == nil {
			t.Fatal("expected error for nil input")
		}
	})

	t.Run("returns error if CEL expression doesn't evaluate to map", func(t *testing.T) {
		mapper, err := NewCELMapper(`"not a map"`)
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		input := &service.MapperInput{}
		_, err = mapper.Map(ctx, input)
		if err == nil {
			t.Fatal("expected error for non-map result")
		}
	})

	t.Run("handles missing datasource gracefully", func(t *testing.T) {
		mapper, err := NewCELMapper(`{
			"has_datasource": datasource("nonexistent") != null,
			"other_field": "value"
		}`)
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		registry := service.NewDataSourceRegistry()
		input := &service.MapperInput{
			DataSourceRegistry: registry,
			DataSourceInput:    &service.DataSourceInput{},
		}

		result, err := mapper.Map(ctx, input)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Should return false for missing datasource
		if result["has_datasource"] != false {
			t.Errorf("expected has_datasource=false for missing datasource, got %v", result["has_datasource"])
		}

		if result["other_field"] != "value" {
			t.Errorf("expected other_field=value, got %v", result["other_field"])
		}
	})
}
