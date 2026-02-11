package trust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"time"

	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/clock"
)

// JWTValidator validates JWT tokens using JWKS
type JWTValidator struct {
	issuer      string
	jwksURL     string
	cache       *jwk.Cache
	trustDomain string
	clock       clock.Clock
}

// JWTValidatorConfig contains configuration for JWT validation
type JWTValidatorConfig struct {
	// Issuer is the expected issuer URL (iss claim)
	Issuer string

	// JWKSURL is the URL to fetch JSON Web Key Set from
	// If empty, will attempt to discover from issuer/.well-known/jwks.json
	JWKSURL string

	// TrustDomain is the trust domain this issuer belongs to
	TrustDomain string

	// RefreshInterval for JWKS cache (default: 15 minutes)
	RefreshInterval time.Duration

	// HTTPClient is an optional HTTP client for JWKS fetching
	// If nil, http.DefaultClient will be used
	// This is useful for testing with fixtures or custom transports
	HTTPClient *http.Client

	// Clock is the time source for token validation
	// If nil, uses system clock
	// This is useful for testing time-dependent behavior
	Clock clock.Clock
}

// NewJWTValidator creates a new JWT validator with JWKS support
func NewJWTValidator(cfg JWTValidatorConfig) (*JWTValidator, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}

	jwksURL := cfg.JWKSURL
	if jwksURL == "" {
		// Default: try standard OIDC discovery endpoint
		jwksURL = cfg.Issuer + "/.well-known/jwks.json"
	}

	refreshInterval := cfg.RefreshInterval
	if refreshInterval == 0 {
		refreshInterval = 15 * time.Minute
	}

	// Create JWKS cache with auto-refresh
	cache, err := jwk.NewCache(context.Background(), httprc.NewClient())
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS cache: %w", err)
	}

	// Register the JWKS URL with the cache
	registerOpts := []jwk.RegisterOption{jwk.WithMinInterval(refreshInterval)}
	if cfg.HTTPClient != nil {
		registerOpts = append(registerOpts, jwk.WithHTTPClient(cfg.HTTPClient))
	}
	if err := cache.Register(context.Background(), jwksURL, registerOpts...); err != nil {
		return nil, fmt.Errorf("failed to register JWKS URL: %w", err)
	}

	// Pre-fetch the JWKS
	// TODO: could make this lazy as opposed to eager fetch on creation
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if _, err := cache.Refresh(ctx, jwksURL); err != nil {
		return nil, fmt.Errorf("failed to fetch initial JWKS: %w", err)
	}

	// Use provided clock or default to system clock
	clk := cfg.Clock
	if clk == nil {
		clk = clock.NewSystemClock()
	}

	return &JWTValidator{
		issuer:      cfg.Issuer,
		jwksURL:     jwksURL,
		cache:       cache,
		trustDomain: cfg.TrustDomain,
		clock:       clk,
	}, nil
}

// CredentialTypes returns the credential types this validator can handle
// JWT validator can handle both JWT and Bearer credentials (since Bearer tokens might be JWTs)
func (v *JWTValidator) CredentialTypes() []CredentialType {
	return []CredentialType{CredentialTypeJWT, CredentialTypeBearer}
}

// Validate validates a JWT credential
func (v *JWTValidator) Validate(ctx context.Context, credential Credential) (*Result, error) {
	// Type assertion to JWTCredential or BearerCredential
	var tokenString string
	switch cred := credential.(type) {
	case *JWTCredential:
		tokenString = cred.Token
	case *BearerCredential:
		// Bearer credentials can also be JWTs
		tokenString = cred.Token
	default:
		return nil, fmt.Errorf("unsupported credential type for JWT validator: %T", credential)
	}

	// Fetch the current JWKS
	jwks, err := v.cache.Lookup(ctx, v.jwksURL)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	// Parse and validate the JWT using the validator's clock
	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(jwks),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.issuer),
		jwt.WithClock(jwt.ClockFunc(func() time.Time {
			return v.clock.Now()
		})),
		// TODO: validate aud
	)
	if err != nil {
		if errors.Is(err, jwt.TokenExpiredError()) {
			return nil, ErrExpiredToken
		}
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	// Ensure there is a subject
	subject, ok := token.Subject()
	if !ok || subject == "" {
		return nil, fmt.Errorf("%w: missing subject claim", ErrInvalidToken)
	}

	// Extract all claims into our Claims type
	allClaims := map[string]any{}
	serialized, err := json.Marshal(token)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize token claims: %w", err)
	}
	if err := json.Unmarshal(serialized, &allClaims); err != nil {
		return nil, fmt.Errorf("failed to parse token claims: %w", err)
	}

	// TODO: Probably should add a ClaimsFilter to validator config so we can configure trust on a per-claim basis
	claimsMap := make(claims.Claims)
	maps.Copy(claimsMap, allClaims)

	// Extract audience
	audiences, _ := token.Audience()

	// Extract scope (OAuth2/OIDC)
	scope := ""
	if err := token.Get("scope", &scope); err != nil {
		scope = ""
	}

	expiresAt, _ := token.Expiration()
	issuedAt, _ := token.IssuedAt()

	return &Result{
		Subject:     subject,
		Issuer:      v.issuer,
		TrustDomain: v.trustDomain,
		Claims:      claimsMap,
		ExpiresAt:   expiresAt,
		IssuedAt:    issuedAt,
		Audience:    audiences,
		Scope:       scope,
	}, nil
}

// Close cleans up resources (stops JWKS cache refresh)
func (v *JWTValidator) Close() error {
	// The cache doesn't have an explicit Close method, but stopping the context
	// used during creation will stop background refreshes.
	// For now, we rely on garbage collection.
	// TODO: reexamine this
	return nil
}
