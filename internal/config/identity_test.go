package config

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestIdentityConfig_CELConfig(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		identity IdentityConfig
		want     map[string]any
	}{
		{
			name:     "empty uses defaults",
			identity: IdentityConfig{},
			want: map[string]any{
				"internal_idp_target":    defaultInternalIDPTarget,
				"role_fallback_enabled": true,
			},
		},
		{
			name: "custom internal idp target",
			identity: IdentityConfig{
				InternalIDPTarget: "https://idp.example.com/realms/internal",
			},
			want: map[string]any{
				"internal_idp_target":    "https://idp.example.com/realms/internal",
				"role_fallback_enabled": true,
			},
		},
		{
			name: "role fallback disabled",
			identity: IdentityConfig{
				RoleFallbackEnabled: boolPtr(false),
			},
			want: map[string]any{
				"internal_idp_target":    defaultInternalIDPTarget,
				"role_fallback_enabled": false,
			},
		},
		{
			name: "role fallback explicitly enabled",
			identity: IdentityConfig{
				RoleFallbackEnabled: boolPtr(true),
			},
			want: map[string]any{
				"internal_idp_target":    defaultInternalIDPTarget,
				"role_fallback_enabled": true,
			},
		},
		{
			name: "all fields set",
			identity: IdentityConfig{
				InternalIDPTarget:     "https://custom.internal/realm",
				RoleFallbackEnabled: boolPtr(false),
			},
			want: map[string]any{
				"internal_idp_target":    "https://custom.internal/realm",
				"role_fallback_enabled": false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := tt.identity.CELConfig()
			require.Equal(t, tt.want, got)
		})
	}
}

func TestNewLoader_IdentityFromEnvironment(t *testing.T) {
	t.Setenv("PARSEC_IDENTITY__INTERNAL_IDP_TARGET", "https://env.example.com/internal")
	t.Setenv("PARSEC_IDENTITY__ROLE_FALLBACK_ENABLED", "false")

	loader, err := NewLoader("")
	require.NoError(t, err)

	cfg, err := loader.Get()
	require.NoError(t, err)

	assert.Equal(t, "https://env.example.com/internal", cfg.Identity.InternalIDPTarget)
	require.NotNil(t, cfg.Identity.RoleFallbackEnabled)
	assert.False(t, *cfg.Identity.RoleFallbackEnabled)

	celCfg := cfg.Identity.CELConfig()
	assert.Equal(t, "https://env.example.com/internal", celCfg["internal_idp_target"])
	assert.Equal(t, false, celCfg["role_fallback_enabled"])
}
