package config

// identityConfigMap builds the CEL config activation map from identity settings.
func identityConfigMap(identity *IdentityConfig) map[string]any {
	if identity == nil {
		return map[string]any{
			"internal_idp_target":   "",
			"role_fallback_enabled": true,
		}
	}
	return map[string]any{
		"internal_idp_target":   identity.InternalIDPTarget,
		"role_fallback_enabled": identity.RoleFallbackEnabled,
	}
}
