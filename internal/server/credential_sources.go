package server

import (
	"context"
	"errors"

	"github.com/project-kessel/parsec/internal/trust"
)

// ErrNoCredentials is returned when none of the configured sources found a
// credential in the transport context.
var ErrNoCredentials = errors.New("no credentials found in configured sources")

// Credential source type strings used in config.
const (
	CredentialSourceTypeBearer = "authorization_bearer_opaque"
	CredentialSourceTypeCookie = "cookie_bearer_opaque"
)

// CredentialSource extracts a credential from a transport-neutral context.
// Implementations handle specific credential presentation protocols (bearer
// header, cookie, etc.).
type CredentialSource interface {
	Extract(ctx context.Context, cc CredentialContext) (*CredentialExtraction, error)
}

// CredentialExtraction is the result of extracting a credential from a request.
type CredentialExtraction struct {
	Credential      trust.Credential
	HeadersToRemove []string
	HeadersToSet    map[string]string
	SourceName      string
}

// CredentialSources is an ordered collection of CredentialSource instances.
// It iterates sources in priority order, returning the first successful
// extraction. This encapsulates the ordering and fallback semantics so
// callers don't manage slices directly.
type CredentialSources struct {
	sources []CredentialSource
}

// NewCredentialSources creates a CredentialSources from individual sources.
func NewCredentialSources(sources ...CredentialSource) CredentialSources {
	return CredentialSources{sources: sources}
}

// DefaultCredentialSources returns the default credential sources
// (authorization bearer only).
func DefaultCredentialSources() CredentialSources {
	return NewCredentialSources(NewBearerCredentialSource(CredentialSourceTypeBearer))
}

// Extract iterates the configured sources in order and returns the first
// successful extraction. Errors from individual sources are collected and
// returned as a joined error when no source succeeds.
func (cs CredentialSources) Extract(ctx context.Context, cc CredentialContext) (*CredentialExtraction, error) {
	if len(cs.sources) == 0 {
		return nil, errors.New("credential sources must not be empty")
	}

	var errs []error
	for _, src := range cs.sources {
		ext, err := src.Extract(ctx, cc)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		if ext != nil {
			return ext, nil
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return nil, ErrNoCredentials
}

// validateCredential validates a credential from a CredentialExtraction against
// a trust.Store.
func validateCredential(ctx context.Context, store trust.Store, ext *CredentialExtraction) (*trust.Result, error) {
	return store.Validate(ctx, ext.Credential)
}
