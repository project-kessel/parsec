package issuer

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jws"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/keys"
	"github.com/project-kessel/parsec/internal/service"
)

// TransactionTokenIssuerConfig is the configuration for creating a transaction token issuer
type TransactionTokenIssuerConfig struct {
	// IssuerURL is the issuer URL (iss claim)
	IssuerURL string

	// TTL is the time-to-live for tokens
	TTL time.Duration

	// Signer handles key rotation and signing (also provides the signing algorithm)
	Signer keys.RotatingSigner

	// TransactionContextMappers build the "tctx" claim
	TransactionContextMappers []service.ClaimMapper

	// RequestContextMappers build the "req_ctx" claim
	RequestContextMappers []service.ClaimMapper

	// Clock is an optional clock for testing (defaults to system clock)
	Clock clock.Clock
}

// TransactionTokenIssuer issues signed transaction tokens per draft-ietf-oauth-transaction-tokens.
// It uses a RotatingSigner for key rotation and signing operations.
type TransactionTokenIssuer struct {
	issuerURL                 string
	ttl                       time.Duration
	signer                    keys.RotatingSigner
	transactionContextMappers []service.ClaimMapper
	requestContextMappers     []service.ClaimMapper
	clock                     clock.Clock
}

// NewTransactionTokenIssuer creates a new transaction token issuer
func NewTransactionTokenIssuer(cfg TransactionTokenIssuerConfig) *TransactionTokenIssuer {
	clk := cfg.Clock
	if clk == nil {
		clk = clock.NewSystemClock()
	}

	return &TransactionTokenIssuer{
		issuerURL:                 cfg.IssuerURL,
		ttl:                       cfg.TTL,
		signer:                    cfg.Signer,
		transactionContextMappers: cfg.TransactionContextMappers,
		requestContextMappers:     cfg.RequestContextMappers,
		clock:                     clk,
	}
}

// Issue implements the Issuer interface
// Issues a signed JWT transaction token per draft-ietf-oauth-transaction-tokens
func (i *TransactionTokenIssuer) Issue(ctx context.Context, issueCtx *service.IssueContext) (*service.Token, error) {
	// Apply transaction context mappers
	transactionContext, err := issueCtx.ToClaims(ctx, i.transactionContextMappers)
	if err != nil {
		return nil, fmt.Errorf("failed to map transaction context: %w", err)
	}

	// Apply request context mappers
	requestContext, err := issueCtx.ToClaims(ctx, i.requestContextMappers)
	if err != nil {
		return nil, fmt.Errorf("failed to map request context: %w", err)
	}

	now := i.clock.Now()
	expiresAt := now.Add(i.ttl)

	// Generate UUIDv7 for transaction ID (provides temporal ordering)
	txnID := uuid.NewString()

	// Build JWT token per draft-ietf-oauth-transaction-tokens
	token := jwt.New()

	// Standard JWT claims
	if err := token.Set(jwt.IssuerKey, i.issuerURL); err != nil {
		return nil, fmt.Errorf("failed to set issuer: %w", err)
	}
	if err := token.Set(jwt.SubjectKey, issueCtx.Subject.Subject); err != nil {
		return nil, fmt.Errorf("failed to set subject: %w", err)
	}
	if err := token.Set(jwt.AudienceKey, []string{issueCtx.Audience}); err != nil {
		return nil, fmt.Errorf("failed to set audience: %w", err)
	}
	if err := token.Set(jwt.IssuedAtKey, now.Unix()); err != nil {
		return nil, fmt.Errorf("failed to set issued at: %w", err)
	}
	if err := token.Set(jwt.ExpirationKey, expiresAt.Unix()); err != nil {
		return nil, fmt.Errorf("failed to set expiration: %w", err)
	}
	if err := token.Set(jwt.NotBeforeKey, now.Unix()); err != nil {
		return nil, fmt.Errorf("failed to set not before: %w", err)
	}
	if err := token.Set(jwt.JwtIDKey, uuid.NewString()); err != nil {
		return nil, fmt.Errorf("failed to set JWT ID: %w", err)
	}

	// Transaction token specific claims
	if err := token.Set("txn", txnID); err != nil {
		return nil, fmt.Errorf("failed to set transaction ID: %w", err)
	}

	// Transaction context (tctx) - authorization context for the transaction
	if len(transactionContext) > 0 {
		if err := token.Set("tctx", transactionContext); err != nil {
			return nil, fmt.Errorf("failed to set transaction context: %w", err)
		}
	}

	// Request context (req_ctx) - information about the request being authorized
	if len(requestContext) > 0 {
		if err := token.Set("req_ctx", requestContext); err != nil {
			return nil, fmt.Errorf("failed to set request context: %w", err)
		}
	}

	// Scope (if provided)
	if issueCtx.Scope != "" {
		if err := token.Set("scope", issueCtx.Scope); err != nil {
			return nil, fmt.Errorf("failed to set scope: %w", err)
		}
	}

	// Get the current signer, key ID, and algorithm from the signer
	signer, keyID, algorithm, err := i.signer.GetCurrentSigner(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get current signer: %w", err)
	}
	signAlg, ok := jwa.LookupSignatureAlgorithm(string(algorithm))
	if !ok {
		return nil, fmt.Errorf("unsupported signature algorithm: %s", algorithm)
	}

	// Build JWS headers with the key ID
	headers := jws.NewHeaders()
	if err := headers.Set(jws.KeyIDKey, string(keyID)); err != nil {
		return nil, fmt.Errorf("failed to set key ID header: %w", err)
	}

	// Sign the token with the current key
	signedToken, err := jwt.Sign(token,
		jwt.WithKey(signAlg, signer, jws.WithProtectedHeaders(headers)))
	if err != nil {
		return nil, fmt.Errorf("failed to sign token: %w", err)
	}

	return &service.Token{
		Value:     string(signedToken),
		Type:      "urn:ietf:params:oauth:token-type:txn_token",
		ExpiresAt: expiresAt,
		IssuedAt:  now,
	}, nil
}

// PublicKeys implements the Issuer interface
// Returns all non-expired public keys from the rotating signer
func (i *TransactionTokenIssuer) PublicKeys(ctx context.Context) ([]service.PublicKey, error) {
	// Get all public keys from the rotating signer (already in service.PublicKey format)
	return i.signer.PublicKeys(ctx)
}
