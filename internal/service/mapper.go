package service

import (
	"context"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/trust"
)

// ClaimMapper transforms inputs into claims for the token
// Claim mappers implement policy logic - what information to include in tokens
type ClaimMapper interface {
	// Map produces claims based on the input
	// Returns nil if the mapper has no claims to contribute
	Map(ctx context.Context, input *MapperInput) (claims.Claims, error)
}

// MapperInput contains all inputs available to a claim mapper
type MapperInput struct {
	// Subject identity (attested claims from validated credential)
	Subject *trust.Result

	// Actor identity (attested claims from actor credential)
	Actor *trust.Result

	// RequestAttributes contains information about the request
	RequestAttributes *request.RequestAttributes

	// DataSourceRegistry provides access to data sources for lazy fetching
	// Mappers can fetch only the data sources they need
	DataSourceRegistry *DataSourceRegistry

	// DataSourceInput is the input to use when fetching from data sources
	DataSourceInput *DataSourceInput
}
