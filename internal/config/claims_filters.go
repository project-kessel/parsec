package config

import (
	"fmt"

	"github.com/project-kessel/parsec/internal/server"
)

// NewClaimsFilterRegistry creates a claims filter registry from configuration
func NewClaimsFilterRegistry(cfg ClaimsFilterConfig) (server.ClaimsFilterRegistry, error) {
	switch cfg.Type {
	case "stub", "":
		// Default to stub (passthrough) filter
		return server.NewStubClaimsFilterRegistry(), nil
	default:
		return nil, fmt.Errorf("unknown claims filter type: %s (supported: stub)", cfg.Type)
	}
}
