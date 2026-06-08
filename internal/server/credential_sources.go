package server

import (
	"context"
	"errors"

	"github.com/project-kessel/parsec/internal/trust"
)

// ErrNoCredentials is returned by extractCredentialFromSources when none of
// the configured sources found a credential in the transport context.
var ErrNoCredentials = errors.New("no credentials found in configured sources")

// Credential source type strings used in config.
const (
	CredentialSourceTypeBearer = "bearer"
	CredentialSourceTypeCookie = "cookie"
	CredentialSourceTypeQuery  = "query"
)

// CredentialSource extracts a credential from a transport-neutral context.
// Implementations handle specific credential presentation protocols (bearer
// header, cookie, query parameter, etc.).
type CredentialSource interface {
	Extract(cc CredentialContext) (*CredentialExtraction, error)
}

// CredentialExtraction is the result of extracting a credential from a request.
type CredentialExtraction struct {
	Credential          trust.Credential
	Headers             []string          // header names to remove entirely
	HeaderSets          map[string]string // header names to set/override on the upstream request
	QueryParamsToRemove []string          // query parameter names to remove before forwarding upstream
	SourceName          string            // configured credential source name
}

// validateCredential validates a credential from a CredentialExtraction against
// a trust.Store and stamps the source name on the result. This encapsulates the
// extract-then-stamp pattern so callers don't mutate Result directly.
func validateCredential(ctx context.Context, store trust.Store, ext *CredentialExtraction) (*trust.Result, error) {
	result, err := store.Validate(ctx, ext.Credential)
	if err != nil {
		return nil, err
	}
	result.CredentialSource = ext.SourceName
	return result, nil
}

func defaultCredentialSources() []CredentialSource {
	return []CredentialSource{&BearerCredentialSource{SourceName: "bearer"}}
}

func extractCredentialFromSources(cc CredentialContext, sources []CredentialSource) (*CredentialExtraction, error) {
	if len(sources) == 0 {
		sources = defaultCredentialSources()
	}

	var lastErr error
	for _, src := range sources {
		ext, err := src.Extract(cc)
		if err != nil {
			lastErr = err
			continue
		}
		if ext != nil {
			return ext, nil
		}
	}

	if lastErr != nil {
		return nil, lastErr
	}
	return nil, ErrNoCredentials
}
