package config

import (
	"fmt"

	"github.com/lestrrat-go/jwx/v2/jwa"

	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/httpfixture"
)

// BuildHTTPFixtureProvider creates a composite HTTP fixture provider from fixture configurations
// Returns nil if no fixtures are configured (normal production mode)
// The returned FixtureProvider provides HTTP fixture serving
func BuildHTTPFixtureProvider(fixtures []FixtureConfig, clk clock.Clock) (httpfixture.FixtureProvider, error) {
	if len(fixtures) == 0 {
		return nil, nil
	}

	if clk == nil {
		clk = clock.NewSystemClock()
	}

	// Build HTTP rule fixtures
	var rules []httpfixture.HTTPFixtureRule
	for _, f := range fixtures {
		if f.Type != "http_rule" {
			continue
		}

		rule := httpfixture.HTTPFixtureRule{
			Request: httpfixture.FixtureRequest{
				Method:  f.Request.Method,
				URL:     f.Request.URL,
				URLType: f.Request.URLType,
				Headers: f.Request.Headers,
			},
			Response: httpfixture.Fixture{
				StatusCode: f.Response.StatusCode,
				Headers:    f.Response.Headers,
				Body:       f.Response.Body,
			},
		}
		rules = append(rules, rule)
	}

	// Build JWKS fixtures
	jwksFixtures := make(map[string]*httpfixture.JWKSFixture)
	for _, f := range fixtures {
		if f.Type != "jwks" {
			continue
		}

		if f.Issuer == "" {
			return nil, fmt.Errorf("jwks fixture missing required field: issuer")
		}
		if f.JWKSURL == "" {
			return nil, fmt.Errorf("jwks fixture for issuer %s missing required field: jwks_url", f.Issuer)
		}

		// Parse algorithm if provided
		var algo jwa.SignatureAlgorithm
		if f.Algorithm != "" {
			algo = jwa.SignatureAlgorithm(f.Algorithm)
		}

		jwksFixture, err := httpfixture.NewJWKSFixture(httpfixture.JWKSFixtureConfig{
			Issuer:    f.Issuer,
			JWKSURL:   f.JWKSURL,
			KeyID:     f.KeyID, // Can be empty, will use default
			Algorithm: algo,    // Can be zero value, will use default
			Clock:     clk,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create JWKS fixture for issuer %s: %w", f.Issuer, err)
		}

		jwksFixtures[f.Issuer] = jwksFixture
	}

	// Build list of providers to compose (always return non-nil, even if empty)
	providers := make([]httpfixture.FixtureProvider, 0)

	if len(rules) > 0 {
		providers = append(providers, httpfixture.NewRuleBasedProvider(rules))
	}

	for _, jwks := range jwksFixtures {
		providers = append(providers, jwks)
	}

	// Always return a valid CompositeFixtureProvider, even if empty
	return httpfixture.NewCompositeFixtureProvider(providers, jwksFixtures), nil
}
