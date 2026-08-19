package mapper

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/clock"
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

	t.Run("now_ms returns fixture clock time", func(t *testing.T) {
		fixedTime := time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC)
		clk := clock.NewFixtureClock(fixedTime)

		mapper, err := NewCELMapper(`{"ts": now_ms()}`, WithClock(clk))
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		result, err := mapper.Map(ctx, &service.MapperInput{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		want := fixedTime.UnixMilli()
		if result.Claims["ts"] != want {
			t.Errorf("expected ts=%d, got %v", want, result.Claims["ts"])
		}
	})

	t.Run("identity-policy datasource exposes settings", func(t *testing.T) {
		mapper, err := NewCELMapper(`{
			"target": datasource("identity-policy").internal_idp_target,
			"fallback": datasource("identity-policy").role_fallback_enabled
		}`)
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		registry := service.NewDataSourceRegistry()
		registry.Register(&mockDataSource{
			name: "identity-policy",
			data: map[string]any{
				"internal_idp_target":   "https://idp.example.com/internal",
				"role_fallback_enabled": false,
			},
		})

		result, err := mapper.Map(ctx, &service.MapperInput{
			DataSourceRegistry: registry,
			DataSourceInput:    &service.DataSourceInput{},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if result.Claims["target"] != "https://idp.example.com/internal" {
			t.Errorf("expected target from datasource, got %v", result.Claims["target"])
		}
		if result.Claims["fallback"] != false {
			t.Errorf("expected fallback=false from datasource, got %v", result.Claims["fallback"])
		}
	})

	t.Run("is_internal uses identity-policy for idp match and role fallback", func(t *testing.T) {
		script := `{
			"is_internal": has(subject.claims.idp) ? (subject.claims.idp == datasource("identity-policy").internal_idp_target) :
			               has(subject.claims.is_internal) ? subject.claims.is_internal :
			               datasource("identity-policy").role_fallback_enabled ? hasRole(subject.claims, "redhat:employees") :
			               false,
			"by_idp": has(subject.claims.idp) ? (subject.claims.idp == datasource("identity-policy").internal_idp_target) : false,
			"by_role": !has(subject.claims.idp) && datasource("identity-policy").role_fallback_enabled ? hasRole(subject.claims, "redhat:employees") : false
		}`
		mapper, err := NewCELMapper(script)
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		registry := service.NewDataSourceRegistry()
		registry.Register(&mockDataSource{
			name: "identity-policy",
			data: map[string]any{
				"internal_idp_target":   "https://sso.redhat.com/auth/realms/internal",
				"role_fallback_enabled": true,
			},
		})
		t.Run("internal idp claim", func(t *testing.T) {
			result, err := mapper.Map(ctx, &service.MapperInput{
				DataSourceRegistry: registry,
				DataSourceInput:    &service.DataSourceInput{},
				Subject: &trust.Result{
					Claims: map[string]any{
						"idp": "https://sso.redhat.com/auth/realms/internal",
					},
				},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Claims["by_idp"] != true {
				t.Errorf("expected by_idp=true for matching idp, got %v", result.Claims["by_idp"])
			}
		})

		t.Run("role fallback skipped when idp present but non-matching", func(t *testing.T) {
			result, err := mapper.Map(ctx, &service.MapperInput{
				DataSourceRegistry: registry,
				DataSourceInput:    &service.DataSourceInput{},
				Subject: &trust.Result{
					Claims: map[string]any{
						"idp": "https://other.example.com/realms/external",
						"realm_access": map[string]any{
							"roles": []any{"redhat:employees"},
						},
					},
				},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Claims["by_idp"] != false {
				t.Errorf("expected by_idp=false for non-matching idp, got %v", result.Claims["by_idp"])
			}
			if result.Claims["by_role"] != false {
				t.Errorf("expected by_role=false when idp present, got %v", result.Claims["by_role"])
			}
		})

		t.Run("role fallback when idp absent", func(t *testing.T) {
			result, err := mapper.Map(ctx, &service.MapperInput{
				DataSourceRegistry: registry,
				DataSourceInput:    &service.DataSourceInput{},
				Subject: &trust.Result{
					Claims: map[string]any{
						"realm_access": map[string]any{
							"roles": []any{"redhat:employees"},
						},
					},
				},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Claims["by_role"] != true {
				t.Errorf("expected by_role=true with employees role, got %v", result.Claims["by_role"])
			}
		})

		t.Run("role fallback disabled", func(t *testing.T) {
			disabledRegistry := service.NewDataSourceRegistry()
			disabledRegistry.Register(&mockDataSource{
				name: "identity-policy",
				data: map[string]any{
					"internal_idp_target":   "https://sso.redhat.com/auth/realms/internal",
					"role_fallback_enabled": false,
				},
			})

			result, err := mapper.Map(ctx, &service.MapperInput{
				DataSourceRegistry: disabledRegistry,
				DataSourceInput:    &service.DataSourceInput{},
				Subject: &trust.Result{
					Claims: map[string]any{
						"realm_access": map[string]any{
							"roles": []any{"redhat:employees"},
						},
					},
				},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Claims["by_role"] != false {
				t.Errorf("expected by_role=false when fallback disabled, got %v", result.Claims["by_role"])
			}
		})

		t.Run("is_internal claim true without idp", func(t *testing.T) {
			result, err := mapper.Map(ctx, &service.MapperInput{
				DataSourceRegistry: registry,
				DataSourceInput:    &service.DataSourceInput{},
				Subject: &trust.Result{
					Claims: map[string]any{
						"is_internal": true,
					},
				},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Claims["is_internal"] != true {
				t.Errorf("expected is_internal=true from claim, got %v", result.Claims["is_internal"])
			}
			if result.Claims["by_idp"] != false {
				t.Errorf("expected by_idp=false without idp, got %v", result.Claims["by_idp"])
			}
			if result.Claims["by_role"] != false {
				t.Errorf("expected by_role=false when is_internal claim present, got %v", result.Claims["by_role"])
			}
		})

		t.Run("external idp overrides is_internal claim for is_internal field", func(t *testing.T) {
			result, err := mapper.Map(ctx, &service.MapperInput{
				DataSourceRegistry: registry,
				DataSourceInput:    &service.DataSourceInput{},
				Subject: &trust.Result{
					Claims: map[string]any{
						"idp":         "https://other.example.com/realms/external",
						"is_internal": true,
					},
				},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Claims["is_internal"] != false {
				t.Errorf("expected is_internal=false when external idp takes precedence, got %v", result.Claims["is_internal"])
			}
			if result.Claims["by_idp"] != false {
				t.Errorf("expected by_idp=false for non-matching idp, got %v", result.Claims["by_idp"])
			}
			if result.Claims["by_role"] != false {
				t.Errorf("expected by_role=false when idp present, got %v", result.Claims["by_role"])
			}
		})

		t.Run("is_internal claim false skips role fallback in is_internal field", func(t *testing.T) {
			result, err := mapper.Map(ctx, &service.MapperInput{
				DataSourceRegistry: registry,
				DataSourceInput:    &service.DataSourceInput{},
				Subject: &trust.Result{
					Claims: map[string]any{
						"is_internal": false,
						"realm_access": map[string]any{
							"roles": []any{"redhat:employees"},
						},
					},
				},
			})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if result.Claims["is_internal"] != false {
				t.Errorf("expected is_internal=false from claim, got %v", result.Claims["is_internal"])
			}
			if result.Claims["by_idp"] != false {
				t.Errorf("expected by_idp=false without idp, got %v", result.Claims["by_idp"])
			}
			if result.Claims["by_role"] != true {
				t.Errorf("expected by_role=true with employees role and no idp, got %v", result.Claims["by_role"])
			}
		})
	})

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

		if result.Claims == nil {
			t.Fatal("expected claims, got nil")
		}
		if !result.Decision.IsAllow() {
			t.Fatalf("expected Allow, got %+v", result.Decision)
		}

		if result.Claims["user"] != "alice" {
			t.Errorf("expected user=alice, got %v", result.Claims["user"])
		}

		if result.Claims["role"] != "admin" {
			t.Errorf("expected role=admin, got %v", result.Claims["role"])
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

		if result.Claims["user"] != "user@example.com" {
			t.Errorf("expected user=user@example.com, got %v", result.Claims["user"])
		}

		if result.Claims["issuer"] != "https://idp.example.com" {
			t.Errorf("expected issuer=https://idp.example.com, got %v", result.Claims["issuer"])
		}

		if result.Claims["trust_domain"] != "example-domain" {
			t.Errorf("expected trust_domain=example-domain, got %v", result.Claims["trust_domain"])
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

		if result.Claims["email"] != "alice@example.com" {
			t.Errorf("expected email=alice@example.com, got %v", result.Claims["email"])
		}

		groups, ok := result.Claims["groups"].([]any)
		if !ok {
			t.Fatalf("expected groups to be array, got %T", result.Claims["groups"])
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

		if result.Claims["actor_id"] != "spiffe://example.com/service/api" {
			t.Errorf("expected actor_id=spiffe://example.com/service/api, got %v", result.Claims["actor_id"])
		}

		if result.Claims["actor_trust_domain"] != "spiffe-domain" {
			t.Errorf("expected actor_trust_domain=spiffe-domain, got %v", result.Claims["actor_trust_domain"])
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

		if result.Claims["method"] != "POST" {
			t.Errorf("expected method=POST, got %v", result.Claims["method"])
		}

		if result.Claims["path"] != "/api/resource" {
			t.Errorf("expected path=/api/resource, got %v", result.Claims["path"])
		}

		if result.Claims["ip"] != "192.168.1.1" {
			t.Errorf("expected ip=192.168.1.1, got %v", result.Claims["ip"])
		}

		if result.Claims["user_agent"] != "test-client/1.0" {
			t.Errorf("expected user_agent=test-client/1.0, got %v", result.Claims["user_agent"])
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

		roles, ok := result.Claims["roles"].([]any)
		if !ok {
			t.Fatalf("expected roles to be array, got %T", result.Claims["roles"])
		}

		if len(roles) != 2 {
			t.Errorf("expected 2 roles, got %d", len(roles))
		}

		if result.Claims["region"] != "us-west-2" {
			t.Errorf("expected region=us-west-2, got %v", result.Claims["region"])
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

		if result.Claims["env"] != "production" {
			t.Errorf("expected env=production, got %v", result.Claims["env"])
		}

		if result.Claims["level"] != "high" {
			t.Errorf("expected level=high, got %v", result.Claims["level"])
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

		if result.Claims["env"] != "dev" {
			t.Errorf("expected env=dev, got %v", result.Claims["env"])
		}

		if result.Claims["level"] != "low" {
			t.Errorf("expected level=low, got %v", result.Claims["level"])
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

		if result.Claims["user"] != "alice" {
			t.Errorf("expected user=alice, got %v", result.Claims["user"])
		}

		if result.Claims["ip"] != "10.0.0.1" {
			t.Errorf("expected ip=10.0.0.1, got %v", result.Claims["ip"])
		}

		if result.Claims["method"] != "GET" {
			t.Errorf("expected method=GET, got %v", result.Claims["method"])
		}

		if result.Claims["computed"] != "alice@10.0.0.1" {
			t.Errorf("expected computed=alice@10.0.0.1, got %v", result.Claims["computed"])
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

		if result.Claims["has_subject"] != false {
			t.Errorf("expected has_subject=false, got %v", result.Claims["has_subject"])
		}

		if result.Claims["has_actor"] != false {
			t.Errorf("expected has_actor=false, got %v", result.Claims["has_actor"])
		}

		if result.Claims["has_request"] != false {
			t.Errorf("expected has_request=false, got %v", result.Claims["has_request"])
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
		if result.Claims["first"] != result.Claims["second"] {
			t.Errorf("expected cached values to match, got first=%v, second=%v",
				result.Claims["first"], result.Claims["second"])
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
		if result.Claims["has_datasource"] != false {
			t.Errorf("expected has_datasource=false for missing datasource, got %v", result.Claims["has_datasource"])
		}

		if result.Claims["other_field"] != "value" {
			t.Errorf("expected other_field=value, got %v", result.Claims["other_field"])
		}
	})
}

func TestCELMapper_Fail(t *testing.T) {
	ctx := context.Background()

	t.Run("fail returns MappingFailure", func(t *testing.T) {
		m, err := NewCELMapper(`false ? {"ok": true} : fail("unsupported_token_type")`)
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		_, mapErr := m.Map(ctx, &service.MapperInput{})
		if mapErr == nil {
			t.Fatal("expected error, got nil")
		}

		var failErr *service.MappingFailure
		if !errors.As(mapErr, &failErr) {
			t.Fatalf("expected errors.As to unwrap MappingFailure, got: %T", mapErr)
		}
		if failErr.Message != "unsupported_token_type" {
			t.Errorf("expected message %q, got %q", "unsupported_token_type", failErr.Message)
		}

		var exchErr *service.ExchangeError
		if errors.As(mapErr, &exchErr) {
			t.Fatal("fail() must not unwrap as ExchangeError")
		}
	})

	t.Run("successful branch does not trigger fail", func(t *testing.T) {
		m, err := NewCELMapper(`true ? {"ok": true} : fail("should_not_reach")`)
		if err != nil {
			t.Fatalf("failed to create mapper: %v", err)
		}

		result, mapErr := m.Map(ctx, &service.MapperInput{})
		if mapErr != nil {
			t.Fatalf("unexpected error: %v", mapErr)
		}
		if result.Claims["ok"] != true {
			t.Errorf("expected ok=true, got %v", result.Claims["ok"])
		}
	})
}

func TestCELMapper_ErrorClaimAllowedInOutput(t *testing.T) {
	ctx := context.Background()

	m, err := NewCELMapper(`{"error": "some_value", "error_code": 403, "other": "data"}`)
	if err != nil {
		t.Fatalf("failed to create mapper: %v", err)
	}

	result, mapErr := m.Map(ctx, &service.MapperInput{})
	if mapErr != nil {
		t.Fatalf("unexpected error: %v", mapErr)
	}

	if result.Claims["error"] != "some_value" {
		t.Errorf("expected error claim preserved as %q, got %v", "some_value", result.Claims["error"])
	}
	if result.Claims["other"] != "data" {
		t.Errorf("expected other claim preserved as %q, got %v", "data", result.Claims["other"])
	}
}

func TestCELMapper_LayerA(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		script     string
		oauthError service.OAuthErrorCode
	}{
		{
			name:       "invalid_request",
			script:     `false ? {"ok": true} : invalidRequest("bad request")`,
			oauthError: service.OAuthInvalidRequest,
		},
		{
			name:       "invalid_target",
			script:     `false ? {"ok": true} : invalidTarget("bad target")`,
			oauthError: service.OAuthInvalidTarget,
		},
		{
			name:       "invalid_grant",
			script:     `false ? {"ok": true} : invalidGrant("bad grant")`,
			oauthError: service.OAuthInvalidGrant,
		},
		{
			name:       "access_denied",
			script:     `false ? {"ok": true} : accessDenied("export compliance check failed")`,
			oauthError: service.OAuthAccessDenied,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewCELMapper(tt.script)
			if err != nil {
				t.Fatalf("failed to create mapper: %v", err)
			}
			result, mapErr := m.Map(ctx, &service.MapperInput{})
			if mapErr != nil {
				t.Fatalf("Deny must not be returned as error, got: %v", mapErr)
			}
			if result.Decision.Action != service.MappingDeny {
				t.Fatalf("expected Deny, got %+v", result.Decision)
			}
			if result.Decision.OAuthError != tt.oauthError {
				t.Errorf("OAuthError: got %q, want %q", result.Decision.OAuthError, tt.oauthError)
			}
			if result.Decision.Reason != "" {
				t.Errorf("Layer A Reason should be empty, got %q", result.Decision.Reason)
			}
		})
	}
}

func TestCELMapper_LayerB(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name       string
		script     string
		oauthError service.OAuthErrorCode
		reason     service.AbortReason
	}{
		{
			name:       "invalid_subject",
			script:     `false ? {"ok": true} : invalidSubject("bad subject")`,
			oauthError: service.OAuthInvalidRequest,
			reason:     service.AbortReasonInvalidSubject,
		},
		{
			name:       "invalid_actor",
			script:     `false ? {"ok": true} : invalidActor("bad actor")`,
			oauthError: service.OAuthInvalidRequest,
			reason:     service.AbortReasonInvalidActor,
		},
		{
			name:       "invalid_audience",
			script:     `false ? {"ok": true} : invalidAudience("bad audience")`,
			oauthError: service.OAuthInvalidTarget,
			reason:     service.AbortReasonInvalidAudience,
		},
		{
			name:       "unsupported_token_type",
			script:     `false ? {"ok": true} : unsupportedTokenType("unsupported_token_type")`,
			oauthError: service.OAuthInvalidRequest,
			reason:     service.AbortReasonUnsupportedTokenType,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m, err := NewCELMapper(tt.script)
			if err != nil {
				t.Fatalf("failed to create mapper: %v", err)
			}
			result, mapErr := m.Map(ctx, &service.MapperInput{})
			if mapErr != nil {
				t.Fatalf("Deny must not be returned as error, got: %v", mapErr)
			}
			if result.Decision.Action != service.MappingDeny {
				t.Fatalf("expected Deny, got %+v", result.Decision)
			}
			if result.Decision.OAuthError != tt.oauthError {
				t.Errorf("OAuthError: got %q, want %q", result.Decision.OAuthError, tt.oauthError)
			}
			if result.Decision.Reason != tt.reason {
				t.Errorf("Reason: got %q, want %q", result.Decision.Reason, tt.reason)
			}
		})
	}
}

func TestCELMapper_PolicyGuard(t *testing.T) {
	ctx := context.Background()

	const policyScript = `
has(subject.claims) && has(subject.claims.impersonated) && subject.claims.impersonated == true
  ? invalidSubject("impersonated tokens are not accepted")
: !(has(subject.claims) && has(subject.claims.idp))
  ? invalidSubject("claim 'idp' is required")
: {"user": subject.subject, "idp": subject.claims.idp}
`

	m, err := NewCELMapper(policyScript)
	if err != nil {
		t.Fatalf("failed to create mapper: %v", err)
	}

	t.Run("rejects_impersonated_token", func(t *testing.T) {
		result, mapErr := m.Map(ctx, &service.MapperInput{
			Subject: &trust.Result{
				Subject: "user-1",
				Claims: claims.Claims{
					"impersonated": true,
					"idp":          "https://idp.example.com",
				},
			},
		})
		assertMappingDeny(t, result, mapErr, service.OAuthInvalidRequest, service.AbortReasonInvalidSubject, "impersonated tokens are not accepted")
	})

	t.Run("accepts_non_impersonated_token", func(t *testing.T) {
		result, mapErr := m.Map(ctx, &service.MapperInput{
			Subject: &trust.Result{
				Subject: "user-1",
				Claims:  claims.Claims{"idp": "https://idp.example.com"},
			},
		})
		if mapErr != nil {
			t.Fatalf("unexpected error: %v", mapErr)
		}
		if result.Claims["user"] != "user-1" {
			t.Errorf("expected user=user-1, got %v", result.Claims["user"])
		}
	})

	t.Run("rejects_missing_idp", func(t *testing.T) {
		result, mapErr := m.Map(ctx, &service.MapperInput{
			Subject: &trust.Result{
				Subject: "user-1",
				Claims:  claims.Claims{"email": "a@b.c"},
			},
		})
		assertMappingDeny(t, result, mapErr, service.OAuthInvalidRequest, service.AbortReasonInvalidSubject, "claim 'idp' is required")
	})

	t.Run("accepts_with_idp", func(t *testing.T) {
		result, mapErr := m.Map(ctx, &service.MapperInput{
			Subject: &trust.Result{
				Subject: "user-1",
				Claims:  claims.Claims{"idp": "https://idp.example.com"},
			},
		})
		if mapErr != nil {
			t.Fatalf("unexpected error: %v", mapErr)
		}
		if result.Claims["idp"] != "https://idp.example.com" {
			t.Errorf("expected idp preserved, got %v", result.Claims["idp"])
		}
	})

	t.Run("rejects_first_failing_guard", func(t *testing.T) {
		result, mapErr := m.Map(ctx, &service.MapperInput{
			Subject: &trust.Result{
				Subject: "user-1",
				Claims: claims.Claims{
					"impersonated": true,
					// idp also missing — impersonation guard must win
				},
			},
		})
		assertMappingDeny(t, result, mapErr, service.OAuthInvalidRequest, service.AbortReasonInvalidSubject, "impersonated tokens are not accepted")
	})

	t.Run("passes_all_guards", func(t *testing.T) {
		result, mapErr := m.Map(ctx, &service.MapperInput{
			Subject: &trust.Result{
				Subject: "user-1",
				Claims:  claims.Claims{"idp": "https://idp.example.com", "impersonated": false},
			},
		})
		if mapErr != nil {
			t.Fatalf("unexpected error: %v", mapErr)
		}
		if result.Claims["user"] != "user-1" {
			t.Errorf("expected user=user-1, got %v", result.Claims["user"])
		}
	})
}

func assertMappingDeny(t *testing.T, result service.MappingResult, err error, oauthError service.OAuthErrorCode, reason service.AbortReason, message string) {
	t.Helper()
	if err != nil {
		t.Fatalf("Deny must not be returned as error, got: %v", err)
	}
	if result.Decision.Action != service.MappingDeny {
		t.Fatalf("expected Deny, got %+v", result.Decision)
	}
	if result.Decision.OAuthError != oauthError {
		t.Errorf("OAuthError: got %q, want %q", result.Decision.OAuthError, oauthError)
	}
	if result.Decision.Reason != reason {
		t.Errorf("Reason: got %q, want %q", result.Decision.Reason, reason)
	}
	if result.Decision.Message != message {
		t.Errorf("Message: got %q, want %q", result.Decision.Message, message)
	}
}
