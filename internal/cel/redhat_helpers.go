package cel

import (
	"os"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// RedHatHelpersLibrary creates a CEL library with helper functions for Red Hat identity logic.
//
// Provides:
//   - hasRole(claims, roleName) - checks if claims.realm_access.roles contains roleName
//   - isInternal(claims) - internal user check (idp vs PARSEC_INTERNAL_IDP_TARGET when set, is_internal claim, optional role fallback)
//   - isConsoleApiToken(claims) - checks if scope contains "api.console"
//   - isServiceAccountToken(claims) - checks if preferred_username starts with "service-account-"
//   - safeToString(val) - converts value to string safely (returns empty string if nil)
func RedHatHelpersLibrary() cel.EnvOption {
	return cel.Lib(&redhatHelpersLib{})
}

type redhatHelpersLib struct{}

func (lib *redhatHelpersLib) CompileOptions() []cel.EnvOption {
	return []cel.EnvOption{
		// hasRole(claims, roleName) - check if a role exists in realm_access.roles
		cel.Function("hasRole",
			cel.Overload("hasRole_map_string",
				[]*cel.Type{cel.DynType, cel.StringType},
				cel.BoolType,
				cel.BinaryBinding(lib.hasRole),
			),
		),

		// isConsoleApiToken(claims) - check if scope contains "api.console"
		cel.Function("isConsoleApiToken",
			cel.Overload("isConsoleApiToken_map",
				[]*cel.Type{cel.DynType},
				cel.BoolType,
				cel.UnaryBinding(lib.isConsoleApiToken),
			),
		),

		// isServiceAccountToken(claims) - check if it's a service account token
		cel.Function("isServiceAccountToken",
			cel.Overload("isServiceAccountToken_map",
				[]*cel.Type{cel.DynType},
				cel.BoolType,
				cel.UnaryBinding(lib.isServiceAccountToken),
			),
		),

		// isInternal(claims) - internal identity (PARSEC_INTERNAL_IDP_TARGET when set, is_internal, PARSEC_INTERNAL_ROLE_FALLBACK)
		cel.Function("isInternal",
			cel.Overload("isInternal_map",
				[]*cel.Type{cel.DynType},
				cel.BoolType,
				cel.UnaryBinding(lib.isInternal),
			),
		),

		// safeToString(val) - convert value to string safely
		cel.Function("safeToString",
			cel.Overload("safeToString_any",
				[]*cel.Type{cel.DynType},
				cel.StringType,
				cel.UnaryBinding(lib.safeToString),
			),
		),
	}
}

func (lib *redhatHelpersLib) ProgramOptions() []cel.ProgramOption {
	return []cel.ProgramOption{}
}

// hasRole checks if claims.realm_access.roles contains the specified role
func (lib *redhatHelpersLib) hasRole(claimsVal, roleVal ref.Val) ref.Val {
	// Extract role name
	roleName, ok := roleVal.Value().(string)
	if !ok {
		return types.Bool(false)
	}

	// Extract claims as map
	claimsMap, ok := claimsVal.Value().(map[string]any)
	if !ok {
		return types.Bool(false)
	}

	// Get realm_access
	realmAccessAny, ok := claimsMap["realm_access"]
	if !ok {
		return types.Bool(false)
	}

	realmAccess, ok := realmAccessAny.(map[string]any)
	if !ok {
		return types.Bool(false)
	}

	// Get roles array
	rolesAny, ok := realmAccess["roles"]
	if !ok {
		return types.Bool(false)
	}

	// Convert to slice
	var roles []any
	switch r := rolesAny.(type) {
	case []any:
		roles = r
	case []string:
		// Convert []string to []any
		roles = make([]any, len(r))
		for i, v := range r {
			roles[i] = v
		}
	default:
		return types.Bool(false)
	}

	// Check if role exists
	for _, role := range roles {
		if roleStr, ok := role.(string); ok && roleStr == roleName {
			return types.Bool(true)
		}
	}

	return types.Bool(false)
}

// isInternal applies a three-tier check: when PARSEC_INTERNAL_IDP_TARGET is set, non-empty string idp vs target; else is_internal claim; else optional hasRole fallback.
func (lib *redhatHelpersLib) isInternal(claimsVal ref.Val) ref.Val {
	claimsMap, ok := claimsVal.Value().(map[string]any)
	if !ok {
		return types.Bool(false)
	}

	// Tier 1: idp claim vs configured target (only when target is set)
	if target, ok := os.LookupEnv("PARSEC_INTERNAL_IDP_TARGET"); ok && target != "" {
		if idpAny, present := claimsMap["idp"]; present {
			idp, ok := idpAny.(string)
			if !ok || idp == "" {
				return types.Bool(false)
			}
			return types.Bool(idp == target)
		}
	}
	// Tier 2: is_internal claim
	if isInternal, ok := claimsMap["is_internal"]; ok {
		if b, ok := isInternal.(bool); ok {
			return types.Bool(b)
		}
	}
	// Tier 3: env-gated role fallback
	if os.Getenv("PARSEC_INTERNAL_ROLE_FALLBACK") != "" {
		return lib.hasRole(claimsVal, types.String("redhat:employees"))
	}
	return types.Bool(false)
}

// isConsoleApiToken checks if the scope claim contains "api.console"
func (lib *redhatHelpersLib) isConsoleApiToken(claimsVal ref.Val) ref.Val {
	claimsMap, ok := claimsVal.Value().(map[string]any)
	if !ok {
		return types.Bool(false)
	}

	scopeAny, ok := claimsMap["scope"]
	if !ok {
		return types.Bool(false)
	}

	scope, ok := scopeAny.(string)
	if !ok {
		return types.Bool(false)
	}

	// Check if "api.console" is in the space-separated scope string
	// Simple implementation - checks if scope contains "api.console"
	// In production, you might want to properly parse space-separated values
	return types.Bool(contains(scope, "api.console"))
}

// isServiceAccountToken checks if preferred_username starts with "service-account-"
func (lib *redhatHelpersLib) isServiceAccountToken(claimsVal ref.Val) ref.Val {
	claimsMap, ok := claimsVal.Value().(map[string]any)
	if !ok {
		return types.Bool(false)
	}

	// Get preferred_username
	usernameAny, ok := claimsMap["preferred_username"]
	if !ok {
		return types.Bool(false)
	}

	username, ok := usernameAny.(string)
	if !ok {
		return types.Bool(false)
	}

	// Check if username starts with "service-account-"
	return types.Bool(len(username) >= 16 && username[:16] == "service-account-")
}

// safeToString converts a value to string safely
func (lib *redhatHelpersLib) safeToString(val ref.Val) ref.Val {
	if val.Type() == types.NullType {
		return types.String("")
	}

	nativeVal := val.Value()
	if nativeVal == nil {
		return types.String("")
	}

	// Try to convert to string using CEL's built-in conversion
	result := types.DefaultTypeAdapter.NativeToValue(nativeVal).ConvertToType(types.StringType)
	if types.IsError(result) {
		// If conversion fails, return empty string
		return types.String("")
	}
	return result
}

// contains checks if a string contains a substring (helper function)
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || findSubstring(s, substr) >= 0)
}

func findSubstring(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
