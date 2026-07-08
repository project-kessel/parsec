package config

import (
	"context"
	"strings"
	"testing"

	"github.com/project-kessel/parsec/internal/observer"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestNewTrustStore_LuaValidatorWithCaching(t *testing.T) {
	const luaScript = `
function validate(input)
  if input.credential.token ~= config.get("expected_token") then
    return nil
  end
  return {
    subject = "lua-user",
    issuer = "https://issuer.example.com",
    trust_domain = "lua.example.com",
    claims = {source = "lua"},
    expires_at = 4102444800
  }
end

function validate_cache_key(input)
  return {
    credential = {
      type = input.credential.type,
      token = input.credential.token
    }
  }
end
`

	store, err := NewTrustStore(TrustStoreConfig{
		Type: "filtered_store",
		Validators: []NamedValidatorConfig{
			{
				Name: "lua-validator",
				ValidatorConfig: ValidatorConfig{
					Type:            "lua_validator",
					Script:          luaScript,
					CredentialTypes: []string{"bearer"},
					Config: map[string]any{
						"expected_token": "valid",
					},
					Caching: &CachingConfig{
						Type: "in_memory",
						TTL:  "10m",
					},
				},
			},
		},
	}, testHTTPRegistry(t), observer.NoOp())
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}

	result, err := store.Validate(context.Background(), &trust.BearerCredential{Token: "valid"})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Subject != "lua-user" {
		t.Fatalf("Subject=%q", result.Subject)
	}
	if result.Claims.GetString("source") != "lua" {
		t.Fatalf("source=%v", result.Claims["source"])
	}
}

func TestNewTrustStore_LuaValidator_BasicAuthCredential(t *testing.T) {
	const luaScript = `
function validate(input)
  local username = input.credential.username
  local password = input.credential.password

  if username == nil or username == "" or password == nil or password == "" then
    return nil
  end

  -- Parse "org_id|username" format
  local pipe_pos = string.find(username, "|", 1, true)
  if pipe_pos == nil then
    return nil
  end

  local org_id = string.sub(username, 1, pipe_pos - 1)
  local parsed_username = string.sub(username, pipe_pos + 1)

  local claims = {}
  if org_id ~= "" then
    claims.org_id = org_id
  end

  return {
    subject = parsed_username,
    issuer = "https://registry.example.com",
    trust_domain = config.get("trust_domain"),
    claims = claims
  }
end

function validate_cache_key(input)
  return {
    credential = {
      type = input.credential.type,
      username = input.credential.username,
      password = input.credential.password
    }
  }
end
`

	store, err := NewTrustStore(TrustStoreConfig{
		Type: "stub_store",
		Validators: []NamedValidatorConfig{
			{
				Name: "registry-auth",
				ValidatorConfig: ValidatorConfig{
					Type:            "lua_validator",
					Script:          luaScript,
					CredentialTypes: []string{"basic_auth"},
					Config: map[string]any{
						"trust_domain": "registry.example.com",
					},
					Caching: &CachingConfig{
						Type: "in_memory",
						TTL:  "5m",
					},
				},
			},
		},
	}, testHTTPRegistry(t), observer.NoOp())
	if err != nil {
		t.Fatalf("NewTrustStore: %v", err)
	}

	result, err := store.Validate(context.Background(), &trust.BasicAuthCredential{
		Username: "123|alice",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if result.Subject != "alice" {
		t.Fatalf("Subject=%q, want alice", result.Subject)
	}
	if result.TrustDomain != "registry.example.com" {
		t.Fatalf("TrustDomain=%q", result.TrustDomain)
	}
	if result.Claims.GetString("org_id") != "123" {
		t.Fatalf("org_id=%v", result.Claims["org_id"])
	}
	// Accepted: no org_id (pipe at start)
	result, err = store.Validate(context.Background(), &trust.BasicAuthCredential{
		Username: "|alice",
		Password: "secret",
	})
	if err != nil {
		t.Fatalf("Validate no-org-id: %v", err)
	}
	if result.Subject != "alice" {
		t.Fatalf("Subject=%q, want alice", result.Subject)
	}
	if result.Claims.Has("org_id") {
		t.Fatalf("org_id should not be set, got %v", result.Claims["org_id"])
	}
	// Rejected: missing pipe separator
	_, err = store.Validate(context.Background(), &trust.BasicAuthCredential{
		Username: "no-pipe",
		Password: "secret",
	})
	if err == nil {
		t.Fatal("expected error for username without pipe separator")
	}

	// Rejected: empty credentials
	_, err = store.Validate(context.Background(), &trust.BasicAuthCredential{
		Username: "",
		Password: "",
	})
	if err == nil {
		t.Fatal("expected error for empty credentials")
	}
}

func TestNewTrustStore_LuaValidator_InvalidCachingType(t *testing.T) {
	t.Parallel()

	const luaScript = `
function validate(input)
  return {
    subject = "user",
    issuer = "https://issuer.example.com",
    trust_domain = "example.com",
  }
end
`
	_, err := NewTrustStore(TrustStoreConfig{
		Type: "stub_store",
		Validators: []NamedValidatorConfig{
			{
				Name: "lua-validator",
				ValidatorConfig: ValidatorConfig{
					Type:            "lua_validator",
					Script:          luaScript,
					CredentialTypes: []string{"bearer"},
					Caching: &CachingConfig{
						Type: "redis",
					},
				},
			},
		},
	}, testHTTPRegistry(t), observer.NoOp())

	if err == nil {
		t.Fatal("expected error for invalid caching type, got nil")
	}
	if !strings.Contains(err.Error(), "unknown validator caching type") {
		t.Fatalf("expected 'unknown validator caching type' error, got: %v", err)
	}
}
