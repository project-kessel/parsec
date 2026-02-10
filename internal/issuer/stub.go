package issuer

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/service"
)

// StubIssuerConfig is the configuration for creating a stub issuer
type StubIssuerConfig struct {
	// IssuerURL is the issuer URL
	IssuerURL string

	// TTL is the time-to-live for issued tokens
	TTL time.Duration

	// TransactionContextMappers are mappers for transaction context
	TransactionContextMappers []service.ClaimMapper

	// RequestContextMappers are mappers for request context
	RequestContextMappers []service.ClaimMapper

	// Clock is the time source for token timestamps
	// If nil, uses system clock
	Clock clock.Clock
}

// StubIssuer is a simple stub issuer for testing
// It generates simple token strings without actual JWT signing
type StubIssuer struct {
	issuerURL                 string
	ttl                       time.Duration
	transactionContextMappers []service.ClaimMapper
	requestContextMappers     []service.ClaimMapper
	clock                     clock.Clock
}

// NewStubIssuer creates a new stub issuer
func NewStubIssuer(cfg StubIssuerConfig) *StubIssuer {
	clk := cfg.Clock
	if clk == nil {
		clk = clock.NewSystemClock()
	}

	return &StubIssuer{
		issuerURL:                 cfg.IssuerURL,
		ttl:                       cfg.TTL,
		transactionContextMappers: cfg.TransactionContextMappers,
		requestContextMappers:     cfg.RequestContextMappers,
		clock:                     clk,
	}
}

// Issue implements the Issuer interface
func (i *StubIssuer) Issue(ctx context.Context, issueCtx *service.IssueContext) (*service.Token, error) {
	// Apply transaction context mappers (currently unused in stub, but kept for consistency)
	_, err := issueCtx.ToClaims(ctx, i.transactionContextMappers)
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

	// Generate a simple token ID with microsecond precision for uniqueness
	txnID := fmt.Sprintf("txn-%d", now.UnixNano()/1000)

	// Include subject from the issue context
	subject := issueCtx.Subject.Subject

	// Encode the request context as JSON so tests can verify filtering
	requestContextJSON, err := json.Marshal(requestContext)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request context: %w", err)
	}

	// Format: stub-txn-token.{subject}.{txnID}.{requestContextJSON}
	tokenValue := fmt.Sprintf("stub-txn-token.%s.%s.%s", subject, txnID, string(requestContextJSON))

	return &service.Token{
		Value:     tokenValue,
		Type:      "urn:ietf:params:oauth:token-type:txn_token",
		ExpiresAt: expiresAt,
		IssuedAt:  now,
	}, nil
}

// PublicKeys implements the Issuer interface
// Stub issuer returns an empty slice since it doesn't sign tokens
func (i *StubIssuer) PublicKeys(ctx context.Context) ([]service.PublicKey, error) {
	// Return empty slice for unsigned stub tokens
	return []service.PublicKey{}, nil
}
