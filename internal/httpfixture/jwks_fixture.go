package httpfixture

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/project-kessel/parsec/internal/clock"
)

// JWKSFixture is a specialized HTTP fixture that serves a JWKS endpoint
// and provides a signing API for creating test tokens with corresponding private keys
type JWKSFixture struct {
	issuer     string
	jwksURL    string
	privateKey *rsa.PrivateKey
	publicKey  jwk.Key
	keyID      string
	algorithm  jwa.SignatureAlgorithm
	jwks       jwk.Set
	clock      clock.Clock
}

// JWKSFixtureConfig configures a JWKS fixture
type JWKSFixtureConfig struct {
	// Issuer is the issuer URL (for iss claim)
	Issuer string

	// JWKSURL is the URL where the JWKS will be served
	JWKSURL string

	// KeyID is the key identifier (kid)
	// If empty, defaults to "test-key-1"
	KeyID string

	// Algorithm is the signing algorithm
	// If zero value, defaults to RS256
	Algorithm jwa.SignatureAlgorithm

	// Clock is the time source for token timestamps
	// If nil, uses system clock
	Clock clock.Clock
}

// NewJWKSFixture creates a new JWKS fixture with a generated RSA key pair
func NewJWKSFixture(cfg JWKSFixtureConfig) (*JWKSFixture, error) {
	if cfg.Issuer == "" {
		return nil, fmt.Errorf("issuer is required")
	}
	if cfg.JWKSURL == "" {
		return nil, fmt.Errorf("jwks_url is required")
	}

	// Set defaults
	keyID := cfg.KeyID
	if keyID == "" {
		keyID = "test-key-1"
	}

	algorithm := cfg.Algorithm
	if algorithm == jwa.EmptySignatureAlgorithm() {
		algorithm = jwa.RS256()
	}

	// Generate RSA key pair
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key: %w", err)
	}

	// Create JWK from public key
	publicKey, err := jwk.Import(privateKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create JWK: %w", err)
	}

	// Set key ID
	if err := publicKey.Set(jwk.KeyIDKey, keyID); err != nil {
		return nil, fmt.Errorf("failed to set key ID: %w", err)
	}

	// Set algorithm
	if err := publicKey.Set(jwk.AlgorithmKey, algorithm); err != nil {
		return nil, fmt.Errorf("failed to set algorithm: %w", err)
	}

	// Create JWKS containing the public key
	jwks := jwk.NewSet()
	if err := jwks.AddKey(publicKey); err != nil {
		return nil, fmt.Errorf("failed to add key to JWKS: %w", err)
	}

	// Use provided clock or default to system clock
	clk := cfg.Clock
	if clk == nil {
		clk = clock.NewSystemClock()
	}

	return &JWKSFixture{
		issuer:     cfg.Issuer,
		jwksURL:    cfg.JWKSURL,
		privateKey: privateKey,
		publicKey:  publicKey,
		keyID:      keyID,
		algorithm:  algorithm,
		jwks:       jwks,
		clock:      clk,
	}, nil
}

// GetFixture implements FixtureProvider interface
// Returns a fixture for JWKS URL requests
func (f *JWKSFixture) GetFixture(req *http.Request) *Fixture {
	// Match the JWKS URL
	if req.URL.String() != f.jwksURL {
		return nil
	}

	// Serialize JWKS to JSON
	jwksJSON, err := json.Marshal(f.jwks)
	if err != nil {
		// This should never happen with a valid JWKS
		return &Fixture{
			StatusCode: 500,
			Body:       fmt.Sprintf(`{"error": "failed to serialize JWKS: %v"}`, err),
		}
	}

	return &Fixture{
		StatusCode: 200,
		Headers: map[string]string{
			"Content-Type": "application/json",
		},
		Body: string(jwksJSON),
	}
}

// JWKSURL returns the JWKS URL this fixture serves
func (f *JWKSFixture) JWKSURL() string {
	return f.jwksURL
}

// Issuer returns the issuer URL
func (f *JWKSFixture) Issuer() string {
	return f.issuer
}

// KeyID returns the key identifier
func (f *JWKSFixture) KeyID() string {
	return f.keyID
}

// Clock returns the clock used by this fixture
func (f *JWKSFixture) Clock() clock.Clock {
	return f.clock
}

// SignToken signs a JWT token using the fixture's private key
func (f *JWKSFixture) SignToken(token jwt.Token) (string, error) {
	// Create JWK from private key with kid for signing
	key, err := jwk.Import(f.privateKey)
	if err != nil {
		return "", fmt.Errorf("failed to create JWK from private key: %w", err)
	}

	if err := key.Set(jwk.KeyIDKey, f.keyID); err != nil {
		return "", fmt.Errorf("failed to set key ID: %w", err)
	}

	if err := key.Set(jwk.AlgorithmKey, f.algorithm); err != nil {
		return "", fmt.Errorf("failed to set algorithm: %w", err)
	}

	// Sign the token
	signed, err := jwt.Sign(token, jwt.WithKey(f.algorithm, key))
	if err != nil {
		return "", fmt.Errorf("failed to sign token: %w", err)
	}

	return string(signed), nil
}

// CreateAndSignToken creates a new JWT with the given claims and signs it
// The issuer, issued-at, and expiration claims are set automatically using the fixture's clock
func (f *JWKSFixture) CreateAndSignToken(claims map[string]interface{}) (string, error) {
	token := jwt.New()

	// Set standard claims using the fixture's clock
	now := f.clock.Now()
	if err := token.Set(jwt.IssuedAtKey, now); err != nil {
		return "", fmt.Errorf("failed to set iat: %w", err)
	}

	if err := token.Set(jwt.ExpirationKey, now.Add(1*time.Hour)); err != nil {
		return "", fmt.Errorf("failed to set exp: %w", err)
	}

	if err := token.Set(jwt.IssuerKey, f.issuer); err != nil {
		return "", fmt.Errorf("failed to set iss: %w", err)
	}

	// Set custom claims
	for key, value := range claims {
		if err := token.Set(key, value); err != nil {
			return "", fmt.Errorf("failed to set claim %s: %w", key, err)
		}
	}

	return f.SignToken(token)
}

// CreateAndSignTokenWithExpiry creates a new JWT with the given claims and custom expiry, and signs it
// Uses the fixture's clock for the issued-at claim
func (f *JWKSFixture) CreateAndSignTokenWithExpiry(claims map[string]interface{}, expiry time.Time) (string, error) {
	token := jwt.New()

	// Set standard claims using the fixture's clock
	now := f.clock.Now()
	if err := token.Set(jwt.IssuedAtKey, now); err != nil {
		return "", fmt.Errorf("failed to set iat: %w", err)
	}

	if err := token.Set(jwt.ExpirationKey, expiry); err != nil {
		return "", fmt.Errorf("failed to set exp: %w", err)
	}

	if err := token.Set(jwt.IssuerKey, f.issuer); err != nil {
		return "", fmt.Errorf("failed to set iss: %w", err)
	}

	// Set custom claims
	for key, value := range claims {
		if err := token.Set(key, value); err != nil {
			return "", fmt.Errorf("failed to set claim %s: %w", key, err)
		}
	}

	return f.SignToken(token)
}
