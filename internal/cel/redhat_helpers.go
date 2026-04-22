package cel

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// RedHatHelpersLibrary creates a CEL library with helper functions for Red Hat identity logic.
//
// Provides:
//   - hasRole(claims, roleName) - checks if claims.realm_access.roles contains roleName
//   - isConsoleApiToken(claims) - checks if scope contains "api.console"
//   - isServiceAccountToken(claims) - checks if preferred_username starts with "service-account-"
//   - safeToString(val) - converts value to string safely (returns empty string if nil)
//   - mergeClaims(base, patch) - shallow-merges claim maps; patch keys with nil values are omitted
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

		// safeToString(val) - convert value to string safely
		cel.Function("safeToString",
			cel.Overload("safeToString_any",
				[]*cel.Type{cel.DynType},
				cel.StringType,
				cel.UnaryBinding(lib.safeToString),
			),
		),
		// mergeClaims(base, patch) - shallow merge map keys from patch over base
		cel.Function("mergeClaims",
			cel.Overload("mergeClaims_dyn_dyn",
				[]*cel.Type{cel.DynType, cel.DynType},
				cel.DynType,
				cel.BinaryBinding(lib.mergeClaims),
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

// mergeClaims shallow-merges two claim maps and returns a new map.
// Patch keys whose value is nil are skipped so CEL can use null to mean "omit this field".
func (lib *redhatHelpersLib) mergeClaims(baseVal, patchVal ref.Val) ref.Val {
	baseNative := ConvertCELValue(baseVal)
	baseMap, ok := baseNative.(map[string]any)
	if !ok {
		return types.NullValue
	}

	patchNative := ConvertCELValue(patchVal)
	patchMap, ok := patchNative.(map[string]any)
	if !ok {
		patchMap = map[string]any{}
	}

	out := make(map[string]any, len(baseMap)+len(patchMap))
	for k, v := range baseMap {
		out[k] = v
	}
	for k, v := range patchMap {
		if v == nil {
			continue
		}
		out[k] = v
	}
	return types.DefaultTypeAdapter.NativeToValue(out)
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
