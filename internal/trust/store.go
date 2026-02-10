package trust

import (
	"context"

	"github.com/project-kessel/parsec/internal/request"
)

// Store manages trust domains and their associated validators
type Store interface {
	// Validate validates a credential, determining the appropriate validator
	// based on the credential type and issuer extracted from the credential
	Validate(ctx context.Context, credential Credential) (*Result, error)

	// ForActor returns a filtered Store that only includes validators
	// the given actor (represented by a Result) is allowed to use.
	// The requestAttrs parameter provides additional context about the request
	// for filtering decisions (e.g., path, headers, envoy context extensions).
	ForActor(ctx context.Context, actor *Result, requestAttrs *request.RequestAttributes) (Store, error)
}
