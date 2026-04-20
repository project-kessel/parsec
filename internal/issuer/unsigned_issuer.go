package issuer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/service"
)

var never = time.Date(9999, 12, 31, 23, 59, 59, 0, time.UTC)

// UnsignedIssuerConfig is the configuration for creating an unsigned issuer
type UnsignedIssuerConfig struct {
	// TokenType is the token type to issue
	TokenType string

	// ClaimMappers are the mappers to apply to generate claims
	ClaimMappers []service.ClaimMapper

	// Clock is the time source for token timestamps
	// If nil, uses system clock
	Clock clock.Clock

	// AuthType is merged into the nested "identity" object when the mapper output
	// includes a top-level "identity" map (e.g. x-rh-identity envelope from CEL).
	// Skipped when that object contains "error".
	AuthType string
}

// UnsignedIssuer issues unsigned tokens containing claim-mapped data
// The token is the base64-encoded JSON representation of the mapped claims
type UnsignedIssuer struct {
	cfg UnsignedIssuerConfig
}

// NewUnsignedIssuer creates a new unsigned issuer
func NewUnsignedIssuer(cfg UnsignedIssuerConfig) *UnsignedIssuer {
	if cfg.Clock == nil {
		cfg.Clock = clock.NewSystemClock()
	}
	return &UnsignedIssuer{cfg: cfg}
}

// enrichIdentityInner sets identity.auth_type. Skips when the mapper returned an error object.
func enrichIdentityInner(inner claims.Claims, authType string) {
	if inner == nil {
		return
	}
	if _, hasErr := inner["error"]; hasErr {
		return
	}
	if authType != "" {
		inner["auth_type"] = authType
	}
}

// Issue implements the Issuer interface
// Returns a token containing base64-encoded JSON of the mapped claims
func (i *UnsignedIssuer) Issue(ctx context.Context, issueCtx *service.IssueContext) (*service.Token, error) {
	mappedClaims, err := issueCtx.ToClaims(ctx, i.cfg.ClaimMappers)
	if err != nil {
		return nil, fmt.Errorf("failed to map claims: %w", err)
	}

	inner := mappedClaims.Copy()
	if i.cfg.AuthType != "" {
		if idVal, ok := inner["identity"]; ok {
			if idMap, ok := idVal.(map[string]any); ok {
				enrichIdentityInner(claims.Claims(idMap), i.cfg.AuthType)
			}
		}
	}

	claimsJSON, err := json.Marshal(inner)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	encodedToken := base64.StdEncoding.EncodeToString(claimsJSON)
	neverExpires := never

	return &service.Token{
		Value:     encodedToken,
		Type:      i.cfg.TokenType,
		ExpiresAt: neverExpires,
		IssuedAt:  i.cfg.Clock.Now(),
	}, nil
}

// PublicKeys implements the Issuer interface
// Unsigned issuer returns an empty slice since tokens are not signed
func (i *UnsignedIssuer) PublicKeys(ctx context.Context) ([]service.PublicKey, error) {
	return []service.PublicKey{}, nil
}
