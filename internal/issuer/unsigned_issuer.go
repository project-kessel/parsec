package issuer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"maps"
	"time"

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

	// IssuerParams are passed to CEL as issuer metadata (issuerParam / issuerPath).
	// Claim-shape logic stays in CEL mapper scripts.
	IssuerParams map[string]any
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

// Issue implements the Issuer interface
// Returns a token containing base64-encoded JSON of the mapped claims
func (i *UnsignedIssuer) Issue(ctx context.Context, issueCtx *service.IssueContext) (*service.Token, error) {
	var opts *service.ToClaimsOptions
	if len(i.cfg.IssuerParams) > 0 {
		opts = &service.ToClaimsOptions{
			IssuerParams: maps.Clone(i.cfg.IssuerParams),
		}
	}

	mappedClaims, err := issueCtx.ToClaims(ctx, i.cfg.ClaimMappers, opts)
	if err != nil {
		return nil, fmt.Errorf("failed to map claims: %w", err)
	}

	inner := mappedClaims.Copy()

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
