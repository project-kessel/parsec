package service

import (
	"context"
	"crypto"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/trust"
)

// IssueContext contains the base information needed to mint any token
// This includes standard fields from token exchange that are always relevant
type IssueContext struct {
	// Subject identity (attested claims from validated credential)
	Subject *trust.Result

	// Actor identity (attested claims from actor credential, e.g., mTLS)
	Actor *trust.Result

	// RequestAttributes contains information about the request
	RequestAttributes *request.RequestAttributes

	// Audience for the token (aud claim) - typically the trust domain
	Audience string

	// Scope for the token (scope claim)
	Scope string

	// DataSourceRegistry provides access to data sources for lazy fetching
	DataSourceRegistry *DataSourceRegistry
}

// ToClaims applies a set of claim mappers to produce claims
// This is a convenience method to reduce duplication in issuer implementations
func (ic *IssueContext) ToClaims(ctx context.Context, mappers []ClaimMapper) (claims.Claims, error) {
	// Build data source input
	dataSourceInput := &DataSourceInput{
		Subject:           ic.Subject,
		Actor:             ic.Actor,
		RequestAttributes: ic.RequestAttributes,
	}

	// Build mapper input
	mapperInput := &MapperInput{
		Subject:            ic.Subject,
		Actor:              ic.Actor,
		RequestAttributes:  ic.RequestAttributes,
		DataSourceRegistry: ic.DataSourceRegistry,
		DataSourceInput:    dataSourceInput,
	}

	// Apply mappers
	result := make(claims.Claims)
	for _, mapper := range mappers {
		mapperClaims, err := mapper.Map(ctx, mapperInput)
		if err != nil {
			return nil, err
		}
		result.Merge(mapperClaims)
	}

	return result, nil
}

// PublicKey represents a public key for token verification
type PublicKey struct {
	// KeyID is the unique identifier for this key (kid)
	KeyID string

	// Algorithm is the signing algorithm (e.g., "RS256", "ES256", "EdDSA")
	Algorithm string

	// Key is the actual public key material
	// Typically: *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey
	Key crypto.PublicKey

	// Use indicates the intended use of the key (e.g., "sig" for signature)
	Use string
}

// Issuer creates signed tokens from issue context
// The issuer is responsible for claim mapping, cryptographic operations, and token formatting
type Issuer interface {
	// Issue creates a token from the provided context
	// The issuer handles all claim mapping internally based on its configuration
	Issue(ctx context.Context, issueCtx *IssueContext) (*Token, error)

	// PublicKeys returns the set of public keys for verifying tokens issued by this issuer
	// Returns an empty slice for unsigned tokens (e.g., stub implementations)
	// The keys may come from various sources: in-memory, JWKS URI, KMS, etc.
	PublicKeys(ctx context.Context) ([]PublicKey, error)
}

// Token represents an issued transaction token
type Token struct {
	// Value is the encoded token (e.g., JWT string)
	Value string

	// Type is the token type (e.g., "urn:ietf:params:oauth:token-type:txn_token")
	Type string

	// ExpiresAt is when the token expires
	ExpiresAt time.Time

	// IssuedAt is when the token was issued
	IssuedAt time.Time
}

// TokenClaims represents the claims in a transaction token
// Based on draft-ietf-oauth-transaction-tokens-06
type TokenClaims struct {
	// Standard JWT claims
	Issuer    string   `json:"iss"`
	Subject   string   `json:"sub"`
	Audience  []string `json:"aud"`
	ExpiresAt int64    `json:"exp"`
	NotBefore int64    `json:"nbf"`
	IssuedAt  int64    `json:"iat"`
	JWTID     string   `json:"jti"`

	// Transaction token specific claims
	TransactionID string `json:"txn"` // UUIDv7 for temporal ordering

	// Transaction context (replaces "azd" from earlier drafts)
	// This is the authorization context for the transaction
	TransactionContext claims.Claims `json:"tctx,omitempty"`

	// Purpose of the token
	Purpose string `json:"purp,omitempty"`

	// Request context - information about the request being authorized
	RequestContext claims.Claims `json:"req_ctx,omitempty"`

	// Scope (OAuth2)
	Scope string `json:"scope,omitempty"`
}
