package server

import (
	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/trust"
)

// ClaimsFilterRegistry determines which request_context claims an actor is allowed to provide
// This is a policy enforcement mechanism - different actors may be trusted to tell us about
// different aspects of the request
type ClaimsFilterRegistry interface {
	// GetFilter returns the ClaimsFilter for the given actor
	// The filter determines which request_context claims the actor is allowed to provide
	GetFilter(actor *trust.Result) (claims.ClaimsFilter, error)
}

// StubClaimsFilterRegistry is a simple stub implementation that allows all claims
// This is useful for testing and initial development
type StubClaimsFilterRegistry struct {
	filter claims.ClaimsFilter
}

// NewStubClaimsFilterRegistry creates a new stub registry
// By default, it uses a passthrough filter that allows all claims
func NewStubClaimsFilterRegistry() *StubClaimsFilterRegistry {
	return &StubClaimsFilterRegistry{
		filter: &claims.PassthroughClaimsFilter{},
	}
}

// NewStubClaimsFilterRegistryWithFilter creates a stub registry with a custom filter
func NewStubClaimsFilterRegistryWithFilter(filter claims.ClaimsFilter) *StubClaimsFilterRegistry {
	return &StubClaimsFilterRegistry{
		filter: filter,
	}
}

// GetFilter implements ClaimsFilterRegistry
func (r *StubClaimsFilterRegistry) GetFilter(actor *trust.Result) (claims.ClaimsFilter, error) {
	return r.filter, nil
}

