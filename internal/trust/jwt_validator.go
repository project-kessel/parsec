package trust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"time"

	"github.com/jwx-go/jwkfetch/v4"
	"github.com/lestrrat-go/httprc/v3"
	"github.com/lestrrat-go/jwx/v4/jwt"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/clock"
)

// JWTValidator validates JWT tokens using JWKS
type JWTValidator struct {
	issuer           string
	jwksURL          string
	cache            *jwkfetch.Cache
	trustDomain      string
	clock            clock.Clock
	observer         JWTValidatorObserver
	allowedAudiences []string
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

	// Observer for JWT validation events. If nil, a no-op observer is used.
	Observer JWTValidatorObserver

	// AllowedAudiences restricts token aud claims. Empty disables enforcement.
	// Include an empty string ("") to permit tokens that omit the aud claim;
	// when aud is present it must match another entry in the list.
	AllowedAudiences []string
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
	var cacheOpts []jwkfetch.CacheOption
	if cfg.HTTPClient != nil {
		cacheOpts = append(cacheOpts, jwkfetch.WithHTTPClient(cfg.HTTPClient))
	}
	cache, err := jwkfetch.NewCache(context.Background(), httprc.NewClient(), cacheOpts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWKS cache: %w", err)
	}

	// Register the JWKS URL with the cache
	registerOpts := []jwkfetch.RegisterOption{jwkfetch.WithMinInterval(refreshInterval)}
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

	obs := cfg.Observer
	if obs == nil {
		obs = NoOpJWTValidatorObserver{}
	}

	return &JWTValidator{
		issuer:           cfg.Issuer,
		jwksURL:          jwksURL,
		cache:            cache,
		trustDomain:      cfg.TrustDomain,
		clock:            clk,
		observer:         obs,
		allowedAudiences: slices.Clone(cfg.AllowedAudiences),
	}, nil
}

// CredentialTypes returns the credential types this validator can handle
// JWT validator can handle both JWT and Bearer credentials (since Bearer tokens might be JWTs)
func (v *JWTValidator) CredentialTypes() []CredentialType {
	return []CredentialType{CredentialTypeJWT, CredentialTypeBearer}
}

// Validate validates a JWT credential
func (v *JWTValidator) Validate(ctx context.Context, credential Credential) (*Result, error) {
	ctx, p := v.observer.JWTValidateStarted(ctx, v.issuer)
	defer p.End()

	var tokenString string
	switch cred := credential.(type) {
	case *JWTCredential:
		tokenString = cred.Token
	case *BearerCredential:
		tokenString = cred.Token
	default:
		return nil, fmt.Errorf("unsupported credential type for JWT validator: %T", credential)
	}

	jwks, err := v.cache.Lookup(ctx, v.jwksURL)
	if err != nil {
		p.JWKSLookupFailed(err)
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}

	token, err := jwt.Parse(
		[]byte(tokenString),
		jwt.WithKeySet(jwks),
		jwt.WithValidate(true),
		jwt.WithIssuer(v.issuer),
		jwt.WithClock(jwt.ClockFunc(func() time.Time {
			return v.clock.Now()
		})),
	)
	if err != nil {
		if errors.Is(err, jwt.TokenExpiredError{}) {
			p.TokenExpired()
			return nil, ErrExpiredToken
		}
		p.TokenInvalid(err)
		return nil, fmt.Errorf("%w: %v", ErrInvalidToken, err)
	}

	subject, ok := token.Subject()
	if !ok || subject == "" {
		return nil, fmt.Errorf("%w: missing subject claim", ErrInvalidToken)
	}

	allClaims := map[string]any{}
	serialized, err := json.Marshal(token)
	if err != nil {
		p.ClaimsExtractionFailed(err)
		return nil, fmt.Errorf("failed to serialize token claims: %w", err)
	}
	if err := json.Unmarshal(serialized, &allClaims); err != nil {
		p.ClaimsExtractionFailed(err)
		return nil, fmt.Errorf("failed to parse token claims: %w", err)
	}

	// TODO: add a ClaimsFilter to validator config for per-claim trust configuration
	claimsMap := make(claims.Claims)
	maps.Copy(claimsMap, allClaims)

	audiences, _ := token.Audience()
	if err := v.validateAudience(audiences); err != nil {
		p.TokenInvalid(err)
		return nil, err
	}

	scope := ""
	if v, ok := token.Field("scope"); ok {
		if s, ok := v.(string); ok {
			scope = s
		}
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

func (v *JWTValidator) validateAudience(tokenAudiences []string) error {
	if len(v.allowedAudiences) == 0 {
		return nil
	}
	allowMissing := slices.Contains(v.allowedAudiences, "")
	if len(tokenAudiences) == 0 {
		if allowMissing {
			return nil
		}
		return fmt.Errorf("%w: missing audience claim", ErrInvalidToken)
	}
	for _, aud := range tokenAudiences {
		if slices.Contains(v.allowedAudiences, aud) {
			return nil
		}
	}
	return fmt.Errorf("%w: audience not in allowlist", ErrInvalidToken)
}

// Close cleans up resources (stops JWKS cache refresh)
func (v *JWTValidator) Close() error {
	// The cache doesn't have an explicit Close method, but stopping the context
	// used during creation will stop background refreshes.
	// For now, we rely on garbage collection.
	// TODO: reexamine this
	return nil
}
