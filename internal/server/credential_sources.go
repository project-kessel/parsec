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
)

// CredentialSource extracts a credential from a transport-neutral context.
// Implementations handle specific credential presentation protocols (bearer
// header, cookie, etc.).
type CredentialSource interface {
	Extract(cc CredentialContext) (*CredentialExtraction, error)
}

// CredentialExtraction is the result of extracting a credential from a request.
type CredentialExtraction struct {
	Credential trust.Credential
	Headers    []string          // header names to remove entirely
	HeaderSets map[string]string // header names to set/override on the upstream request
	SourceName string            // configured credential source name
}

// validateCredential validates a credential from a CredentialExtraction against
// a trust.Store.
func validateCredential(ctx context.Context, store trust.Store, ext *CredentialExtraction) (*trust.Result, error) {
	return store.Validate(ctx, ext.Credential)
}

func defaultCredentialSources() []CredentialSource {
	return []CredentialSource{&BearerCredentialSource{SourceName: "bearer"}}
}

func extractCredentialFromSources(cc CredentialContext, sources []CredentialSource) (*CredentialExtraction, error) {
	if len(sources) == 0 {
		sources = defaultCredentialSources()
	}

	var errs []error
	for _, src := range sources {
		ext, err := src.Extract(cc)
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
