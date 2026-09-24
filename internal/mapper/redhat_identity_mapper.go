package mapper

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/service"
)

type identityPolicy struct {
	InternalIDPTarget   string `json:"internal_idp_target"`
	RoleFallbackEnabled bool   `json:"role_fallback_enabled"`
}

// RedHatIdentityMapper transforms JWT claims into a Red Hat x-rh-identity
// envelope. It is a Go-native replacement for redhat_identity.cel.
//
// Token type classification follows this priority order:
//  1. Registry Auth (issuer contains "container-registry-authorizer" and "api.redhat.com")
//  2. Service Account (preferred_username starts with "service-account-")
//  3. Console API (scope contains "api.console")
//  4. RHSM API (audience contains "rhsm-api")
//  5. Customer Portal (audience contains "customer-portal")
type RedHatIdentityMapper struct {
	clock clock.Clock
}

type RedHatIdentityMapperOption func(*redHatIdentityMapperConfig)

type redHatIdentityMapperConfig struct {
	clock clock.Clock
}

func WithRedHatIdentityClock(clk clock.Clock) RedHatIdentityMapperOption {
	return func(cfg *redHatIdentityMapperConfig) {
		cfg.clock = clk
	}
}

func NewRedHatIdentityMapper(opts ...RedHatIdentityMapperOption) *RedHatIdentityMapper {
	cfg := &redHatIdentityMapperConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.clock == nil {
		cfg.clock = clock.NewSystemClock()
	}
	return &RedHatIdentityMapper{clock: cfg.clock}
}

func (m *RedHatIdentityMapper) Map(ctx context.Context, input *service.MapperInput) (service.MappingResult, error) {
	if input == nil {
		return service.MappingResult{}, fmt.Errorf("mapper input cannot be nil")
	}

	sub := input.Subject
	var c map[string]any
	if sub != nil && len(sub.Claims) > 0 {
		c = map[string]any(sub.Claims)
	}

	if c != nil {
		if imp, _ := c["impersonated"].(bool); imp {
			return service.DenyReason(service.AbortReasonInvalidSubject, "impersonated tokens are not accepted"), nil
		}
	}

	if sub != nil && isRegistryAuthIssuer(sub.Issuer) {
		return m.mapRegistryAuth(c, input), nil
	}

	if c != nil && isServiceAccountToken(c) {
		return m.mapServiceAccount(c, input)
	}

	if c != nil && isConsoleApiToken(c) {
		if _, hasIDP := c["idp"]; !hasIDP {
			return service.DenyReason(service.AbortReasonInvalidSubject, "claim 'idp' is required"), nil
		}
		return m.mapConsoleAPI(ctx, c, input)
	}

	if sub != nil && containsString(sub.Audience, "rhsm-api") {
		return m.mapRHSMAPI(ctx, c, input)
	}

	if sub != nil && containsString(sub.Audience, "customer-portal") {
		return m.mapCustomerPortal(ctx, c, input)
	}

	return service.DenyReason(service.AbortReasonUnsupportedTokenType, "unsupported_token_type"), nil
}

func (m *RedHatIdentityMapper) mapRegistryAuth(c map[string]any, input *service.MapperInput) service.MappingResult {
	var orgID any
	if c != nil {
		orgID = c["org_id"]
	}

	return service.AllowResult(claims.Claims{
		"identity": map[string]any{
			"auth_type": "registry-auth",
			"org_id":    orgID,
			"type":      "User",
			"user": map[string]any{
				"username": input.Subject.Subject,
			},
			"internal": map[string]any{
				"org_id":       orgID,
				"cross_access": false,
				"auth_time":    m.clock.Now().UnixMilli(),
			},
		},
		"entitlements": map[string]any{},
	})
}

func (m *RedHatIdentityMapper) mapServiceAccount(c map[string]any, input *service.MapperInput) (service.MappingResult, error) {
	org := nestedMap(c, "organization")

	orgID := stringClaim(c, "rh-org-id")
	if orgID == "" {
		orgID = stringClaim(org, "id")
	}

	clientID := stringClaim(c, "client_id")
	if clientID == "" {
		clientID = stringClaim(c, "clientId")
	}
	if clientID == "" {
		return service.MappingResult{}, &service.MappingFailure{Message: "missing_client_id"}
	}

	return service.AllowResult(claims.Claims{
		"identity": map[string]any{
			"auth_type":      "jwt-auth",
			"account_number": stringClaim(org, "account_number"),
			"org_id":         orgID,
			"type":           "ServiceAccount",
			"service_account": map[string]any{
				"username":  stringClaim(c, "preferred_username"),
				"client_id": clientID,
				"user_id":   stringClaim(c, "sub"),
				"scope":     stringClaim(c, "scope"),
			},
			"internal": map[string]any{
				"org_id":       orgID,
				"cross_access": false,
				"auth_time":    m.authTime(c),
			},
		},
		"entitlements": map[string]any{},
	}), nil
}

func (m *RedHatIdentityMapper) mapConsoleAPI(ctx context.Context, c map[string]any, input *service.MapperInput) (service.MappingResult, error) {
	policy, err := fetchIdentityPolicy(ctx, input)
	if err != nil {
		return service.MappingResult{}, err
	}

	org := nestedMap(c, "organization")
	orgID := stringClaim(org, "id")

	return service.AllowResult(claims.Claims{
		"identity": map[string]any{
			"auth_type":      "jwt-auth",
			"account_number": stringClaim(org, "account_number"),
			"org_id":         orgID,
			"type":           "User",
			"user": map[string]any{
				"username":     stringClaim(c, "preferred_username"),
				"email":        stringClaim(c, "email"),
				"first_name":   stringClaim(c, "given_name"),
				"last_name":    stringClaim(c, "family_name"),
				"is_active":    true,
				"is_org_admin": hasRole(c, "admin:org:all"),
				"is_internal":  isInternalConsoleAPI(c, policy),
				"locale":       stringClaim(c, "locale"),
				"user_id":      safeToString(c["user_id"]),
			},
			"internal": map[string]any{
				"org_id":       orgID,
				"cross_access": false,
				"auth_time":    m.authTime(c),
			},
		},
		"entitlements": map[string]any{},
	}), nil
}

func (m *RedHatIdentityMapper) mapRHSMAPI(ctx context.Context, c map[string]any, input *service.MapperInput) (service.MappingResult, error) {
	policy, err := fetchIdentityPolicy(ctx, input)
	if err != nil {
		return service.MappingResult{}, err
	}

	org := nestedMap(c, "organization")

	orgID := stringClaim(org, "id")
	if orgID == "" {
		orgID = safeToString(c["org_id"])
	}
	if orgID == "" {
		orgID = safeToString(c["account_id"])
	}

	return service.AllowResult(claims.Claims{
		"identity": map[string]any{
			"auth_type":      "jwt-auth",
			"account_number": safeToString(c["account_id"]),
			"org_id":         orgID,
			"type":           "User",
			"user": map[string]any{
				"username":     firstString(c, "preferred_username", "username"),
				"email":        stringClaim(c, "email"),
				"first_name":   firstString(c, "given_name", "firstName"),
				"last_name":    firstString(c, "family_name", "lastName"),
				"is_active":    true,
				"is_org_admin": hasRole(c, "admin:org:all"),
				"is_internal":  isInternalAudienceBased(c, policy),
				"locale":       firstString(c, "locale", "lang"),
				"user_id":      firstSafeString(c, "sub", "user_id"),
			},
			"internal": map[string]any{
				"org_id":       orgID,
				"cross_access": false,
				"auth_time":    m.authTime(c),
			},
		},
		"entitlements": map[string]any{},
	}), nil
}

func (m *RedHatIdentityMapper) mapCustomerPortal(ctx context.Context, c map[string]any, input *service.MapperInput) (service.MappingResult, error) {
	policy, err := fetchIdentityPolicy(ctx, input)
	if err != nil {
		return service.MappingResult{}, err
	}

	org := nestedMap(c, "organization")

	accountNumber := safeToString(c["account_number"])
	if accountNumber == "" {
		accountNumber = stringClaim(org, "account_number")
	}

	orgID := stringClaim(org, "id")
	if orgID == "" {
		orgID = safeToString(c["org_id"])
	}

	return service.AllowResult(claims.Claims{
		"identity": map[string]any{
			"auth_type":      "jwt-auth",
			"account_number": accountNumber,
			"org_id":         orgID,
			"type":           "User",
			"user": map[string]any{
				"username":     firstString(c, "username", "preferred_username"),
				"email":        stringClaim(c, "email"),
				"first_name":   firstString(c, "firstName", "given_name"),
				"last_name":    firstString(c, "lastName", "family_name"),
				"is_active":    true,
				"is_org_admin": hasRole(c, "admin:org:all"),
				"is_internal":  isInternalAudienceBased(c, policy),
				"locale":       firstString(c, "lang", "locale"),
				"user_id":      firstSafeString(c, "user_id", "sub"),
			},
			"internal": map[string]any{
				"org_id":       orgID,
				"cross_access": false,
				"auth_time":    m.authTime(c),
			},
		},
		"entitlements": map[string]any{},
	}), nil
}

// authTime returns iat*1000 if the iat claim exists, otherwise now in millis.
func (m *RedHatIdentityMapper) authTime(c map[string]any) int64 {
	if c == nil {
		return m.clock.Now().UnixMilli()
	}
	if iat, ok := c["iat"]; ok {
		switch v := iat.(type) {
		case float64:
			return int64(v) * 1000
		case int64:
			return v * 1000
		case int:
			return int64(v) * 1000
		}
	}
	return m.clock.Now().UnixMilli()
}

func fetchIdentityPolicy(ctx context.Context, input *service.MapperInput) (*identityPolicy, error) {
	if input.DataSourceRegistry == nil {
		return &identityPolicy{}, nil
	}
	ds := input.DataSourceRegistry.Get("identity-policy")
	if ds == nil {
		return &identityPolicy{}, nil
	}
	result, err := ds.Fetch(ctx, input.DataSourceInput)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch identity-policy: %w", err)
	}
	if result == nil {
		return &identityPolicy{}, nil
	}
	var policy identityPolicy
	if err := json.Unmarshal(result.Data, &policy); err != nil {
		return nil, fmt.Errorf("failed to unmarshal identity-policy: %w", err)
	}
	return &policy, nil
}

// isInternalConsoleAPI determines is_internal for console API tokens.
// Console API tokens always have an idp claim (enforced by the caller).
// If idp matches the target, returns true. Otherwise falls through to
// is_internal claim check and role-based fallback.
func isInternalConsoleAPI(c map[string]any, policy *identityPolicy) bool {
	idp, _ := c["idp"].(string)
	if idp == policy.InternalIDPTarget {
		return true
	}
	if v, ok := c["is_internal"]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	if policy.RoleFallbackEnabled {
		return hasRole(c, "redhat:employees")
	}
	return false
}

// isInternalAudienceBased determines is_internal for RHSM and Customer Portal tokens.
// If the idp claim exists, it is the definitive indicator (matches target or not).
// If absent, falls through to is_internal claim check and role-based fallback.
func isInternalAudienceBased(c map[string]any, policy *identityPolicy) bool {
	if idpVal, hasIDP := c["idp"]; hasIDP {
		idp, _ := idpVal.(string)
		return idp == policy.InternalIDPTarget
	}
	if v, ok := c["is_internal"]; ok {
		if b, ok := v.(bool); ok {
			return b
		}
	}
	if policy.RoleFallbackEnabled {
		return hasRole(c, "redhat:employees")
	}
	return false
}

func isRegistryAuthIssuer(issuer string) bool {
	return strings.Contains(issuer, "container-registry-authorizer") && strings.Contains(issuer, "api.redhat.com")
}

func isServiceAccountToken(c map[string]any) bool {
	username, _ := c["preferred_username"].(string)
	return strings.HasPrefix(username, "service-account-")
}

func isConsoleApiToken(c map[string]any) bool {
	scope, _ := c["scope"].(string)
	return strings.Contains(scope, "api.console")
}

func hasRole(c map[string]any, roleName string) bool {
	realmAccess, ok := c["realm_access"].(map[string]any)
	if !ok {
		return false
	}
	roles, ok := realmAccess["roles"]
	if !ok {
		return false
	}
	switch r := roles.(type) {
	case []any:
		for _, role := range r {
			if s, ok := role.(string); ok && s == roleName {
				return true
			}
		}
	case []string:
		for _, role := range r {
			if role == roleName {
				return true
			}
		}
	}
	return false
}

func containsString(slice []string, target string) bool {
	for _, s := range slice {
		if s == target {
			return true
		}
	}
	return false
}

func stringClaim(c map[string]any, key string) string {
	if c == nil {
		return ""
	}
	s, _ := c[key].(string)
	return s
}

func nestedMap(c map[string]any, key string) map[string]any {
	if c == nil {
		return nil
	}
	m, _ := c[key].(map[string]any)
	return m
}

func safeToString(val any) string {
	if val == nil {
		return ""
	}
	return fmt.Sprintf("%v", val)
}

// firstString returns the first non-empty string claim from the given keys.
func firstString(c map[string]any, keys ...string) string {
	for _, key := range keys {
		if s := stringClaim(c, key); s != "" {
			return s
		}
	}
	return ""
}

// firstSafeString returns safeToString of the first present claim from the given keys.
func firstSafeString(c map[string]any, keys ...string) string {
	for _, key := range keys {
		if v, ok := c[key]; ok {
			return safeToString(v)
		}
	}
	return ""
}
