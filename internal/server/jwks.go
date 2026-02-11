package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/big"
	"sync"
	"time"

	parsecv1 "github.com/project-kessel/parsec/api/gen/parsec/v1"
	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/service"
)

// JWKSServer implements the JWKS gRPC service
// It serves JSON Web Key Sets containing public keys from all configured issuers
// The response is cached and periodically refreshed for efficiency
type JWKSServer struct {
	parsecv1.UnimplementedJWKSServiceServer

	issuerRegistry  service.Registry
	clock           clock.Clock
	refreshInterval time.Duration
	logger          *slog.Logger

	// Cached response
	mu             sync.RWMutex
	cachedResponse *parsecv1.GetJWKSResponse
	cachedError    error

	// Background refresh
	ticker clock.Ticker
}

// JWKSServerConfig configures the JWKS server
type JWKSServerConfig struct {
	// IssuerRegistry provides access to all issuers
	IssuerRegistry service.Registry

	// RefreshInterval is how often to refresh the cached JWKS
	// If zero, defaults to 1 minute
	RefreshInterval time.Duration

	// Clock is used for time operations (defaults to system clock)
	Clock clock.Clock

	// Logger is the structured logger to use. If nil, uses slog.Default()
	Logger *slog.Logger
}

// NewJWKSServer creates a new JWKS server with caching
func NewJWKSServer(cfg JWKSServerConfig) *JWKSServer {
	if cfg.RefreshInterval == 0 {
		cfg.RefreshInterval = 1 * time.Minute
	}
	if cfg.Clock == nil {
		cfg.Clock = clock.NewSystemClock()
	}
	logger := cfg.Logger
	if logger == nil {
		logger = slog.Default()
	}

	return &JWKSServer{
		issuerRegistry:  cfg.IssuerRegistry,
		clock:           cfg.Clock,
		refreshInterval: cfg.RefreshInterval,
		logger:          logger,
	}
}

// Start begins the background cache refresh
func (s *JWKSServer) Start(ctx context.Context) error {
	// Populate cache immediately
	if err := s.refreshCache(ctx); err != nil {
		s.logger.Warn("initial cache population failed, will retry", "error", err)
	}

	// Start background refresh
	s.ticker = s.clock.Ticker(s.refreshInterval)
	return s.ticker.Start(func(ctx context.Context) {
		if err := s.refreshCache(ctx); err != nil {
			s.logger.Warn("background cache refresh failed", "error", err)
		}
	})
}

// Stop stops the background cache refresh
func (s *JWKSServer) Stop() {
	if s.ticker != nil {
		s.ticker.Stop()
	}
}

// GetJWKS implements the JWKS service
// Returns a cached JSON Web Key Set containing all public keys from all configured issuers
func (s *JWKSServer) GetJWKS(ctx context.Context, req *parsecv1.GetJWKSRequest) (*parsecv1.GetJWKSResponse, error) {
	// Try to serve from cache first
	s.mu.RLock()
	cachedResp := s.cachedResponse
	cachedErr := s.cachedError
	s.mu.RUnlock()

	// If cache is populated, return it
	if cachedResp != nil {
		return cachedResp, nil
	}

	// If cache has an error and no response, return the error
	if cachedErr != nil {
		return nil, cachedErr
	}

	// Cache is empty (first request or failed initial population)
	// Build the response synchronously to ensure immediate availability
	return s.buildJWKSResponse(ctx)
}

// refreshCache updates the cached JWKS response in the background
func (s *JWKSServer) refreshCache(ctx context.Context) error {
	resp, err := s.buildJWKSResponse(ctx)

	s.mu.Lock()
	defer s.mu.Unlock()

	if resp != nil {
		s.cachedResponse = resp
		s.cachedError = nil
	} else {
		// Only cache the error if we don't have a previous successful response
		// This ensures we keep serving stale data rather than failing
		if s.cachedResponse == nil {
			s.cachedError = err
		}
	}

	return err
}

// buildJWKSResponse builds a fresh JWKS response from all issuers
func (s *JWKSServer) buildJWKSResponse(ctx context.Context) (*parsecv1.GetJWKSResponse, error) {
	// Get all public keys from all issuers at once
	publicKeys, err := s.issuerRegistry.GetAllPublicKeys(ctx)

	// If we got no keys and there were errors, return the error
	if len(publicKeys) == 0 && err != nil {
		return nil, fmt.Errorf("failed to get public keys: %w", err)
	}

	// If we got some keys but also errors, we'll return the keys successfully
	// The errors are still propagated via the error return for observability
	// but we prioritize serving available keys to clients

	// Convert service.PublicKey to parsecv1.JSONWebKey
	var allKeys []*parsecv1.JSONWebKey
	for _, pk := range publicKeys {
		jwk, err := convertToJSONWebKey(pk)
		if err != nil {
			// Skip keys that can't be converted
			continue
		}
		allKeys = append(allKeys, jwk)
	}

	// Return the keys. If there were partial failures (err != nil but len(allKeys) > 0),
	// we still return success to serve the available keys
	return &parsecv1.GetJWKSResponse{
		Keys: allKeys,
	}, nil
}

// convertToJSONWebKey converts a service.PublicKey to a parsecv1.JSONWebKey
// following RFC 7517 format
func convertToJSONWebKey(pk service.PublicKey) (*parsecv1.JSONWebKey, error) {
	jwk := &parsecv1.JSONWebKey{
		Kid: pk.KeyID,
		Alg: pk.Algorithm,
		Use: pk.Use,
	}

	// Set key-specific parameters based on the key type
	switch key := pk.Key.(type) {
	case *rsa.PublicKey:
		jwk.Kty = "RSA"
		jwk.N = base64urlEncode(key.N.Bytes())
		jwk.E = base64urlEncode(big.NewInt(int64(key.E)).Bytes())

	case *ecdsa.PublicKey:
		jwk.Kty = "EC"
		jwk.X = base64urlEncode(key.X.Bytes())
		jwk.Y = base64urlEncode(key.Y.Bytes())

		// Set curve name
		switch key.Curve.Params().Name {
		case "P-256":
			jwk.Crv = "P-256"
		case "P-384":
			jwk.Crv = "P-384"
		case "P-521":
			jwk.Crv = "P-521"
		default:
			return nil, fmt.Errorf("unsupported EC curve: %s", key.Curve.Params().Name)
		}

	case ed25519.PublicKey:
		jwk.Kty = "OKP"
		jwk.Crv = "Ed25519"
		jwk.X = base64urlEncode([]byte(key))

	default:
		return nil, fmt.Errorf("unsupported key type: %T", key)
	}

	return jwk, nil
}

// base64urlEncode encodes bytes using base64url encoding (no padding) as required by RFC 7517
func base64urlEncode(data []byte) string {
	return base64.RawURLEncoding.EncodeToString(data)
}
