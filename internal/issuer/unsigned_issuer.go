package issuer

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
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
}

// UnsignedIssuer issues unsigned tokens containing claim-mapped data.
// The payload is base64-encoded JSON: raw mapped claims, except for
// TokenTypeRHIdentity where the JSON is {"identity": <mapped claims>} (x-rh-identity).
type UnsignedIssuer struct {
	tokenType    string
	claimMappers []service.ClaimMapper
	clock        clock.Clock
}

// NewUnsignedIssuer creates a new unsigned issuer
func NewUnsignedIssuer(cfg UnsignedIssuerConfig) *UnsignedIssuer {
	clk := cfg.Clock
	if clk == nil {
		clk = clock.NewSystemClock()
	}

	return &UnsignedIssuer{
		tokenType:    cfg.TokenType,
		claimMappers: cfg.ClaimMappers,
		clock:        clk,
	}
}

// Issue implements the Issuer interface
// Returns a token containing base64-encoded JSON of the mapped claims.
// For TokenTypeRHIdentity, JSON matches x-rh-identity: {"identity": <mapped claims>},
// same as RHIdentityIssuer (so fields like identity.error are addressable).
func (i *UnsignedIssuer) Issue(ctx context.Context, issueCtx *service.IssueContext) (*service.Token, error) {
	// Apply claim mappers
	mappedClaims, err := issueCtx.ToClaims(ctx, i.claimMappers)
	if err != nil {
		return nil, fmt.Errorf("failed to map claims: %w", err)
	}

	payload := any(mappedClaims)
	if service.TokenType(i.tokenType) == service.TokenTypeRHIdentity {
		payload = map[string]any{"identity": mappedClaims}
	}

	claimsJSON, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims: %w", err)
	}

	// Base64-encode the JSON
	encodedToken := base64.StdEncoding.EncodeToString(claimsJSON)

	// Use a far-future expiration time to indicate the token never expires
	neverExpires := never

	return &service.Token{
		Value:     encodedToken,
		Type:      i.tokenType,
		ExpiresAt: neverExpires,
		IssuedAt:  i.clock.Now(),
	}, nil
}

// PublicKeys implements the Issuer interface
// Unsigned issuer returns an empty slice since tokens are not signed
func (i *UnsignedIssuer) PublicKeys(ctx context.Context) ([]service.PublicKey, error) {
	return []service.PublicKey{}, nil
}
