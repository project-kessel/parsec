package service

import (
	"context"
	"maps"

	"github.com/project-kessel/parsec/internal/claims"
)

// StubClaimMapper is a simple stub claim mapper for testing
type StubClaimMapper struct {
	claims claims.Claims
}

// NewStubClaimMapper creates a new stub claim mapper
func NewStubClaimMapper(c claims.Claims) *StubClaimMapper {
	return &StubClaimMapper{
		claims: c,
	}
}

// Map implements the ClaimMapper interface
func (s *StubClaimMapper) Map(ctx context.Context, input *MapperInput) (claims.Claims, error) {
	return s.claims, nil
}

// PassthroughSubjectMapper creates claims from the subject's validated claims
type PassthroughSubjectMapper struct{}

// NewPassthroughSubjectMapper creates a mapper that passes through subject claims
func NewPassthroughSubjectMapper() *PassthroughSubjectMapper {
	return &PassthroughSubjectMapper{}
}

// Map implements the ClaimMapper interface
func (p *PassthroughSubjectMapper) Map(ctx context.Context, input *MapperInput) (claims.Claims, error) {
	if input.Subject == nil {
		return nil, nil
	}
	return input.Subject.Claims, nil
}

// RequestAttributesMapper creates claims from request attributes
type RequestAttributesMapper struct{}

// NewRequestAttributesMapper creates a mapper that includes request attributes
func NewRequestAttributesMapper() *RequestAttributesMapper {
	return &RequestAttributesMapper{}
}

// Map implements the ClaimMapper interface
func (r *RequestAttributesMapper) Map(ctx context.Context, input *MapperInput) (claims.Claims, error) {
	if input.RequestAttributes == nil {
		return nil, nil
	}

	result := make(claims.Claims)
	if input.RequestAttributes.Method != "" {
		result["method"] = input.RequestAttributes.Method
	}
	if input.RequestAttributes.Path != "" {
		result["path"] = input.RequestAttributes.Path
	}
	if input.RequestAttributes.IPAddress != "" {
		result["ip_address"] = input.RequestAttributes.IPAddress
	}
	if input.RequestAttributes.UserAgent != "" {
		result["user_agent"] = input.RequestAttributes.UserAgent
	}

	// Include all items from Additional map
	maps.Copy(result, input.RequestAttributes.Additional)

	return result, nil
}
