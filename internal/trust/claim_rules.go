package trust

import (
	"fmt"
	"slices"
	"time"
)

// ClaimRules enforces JWT claim policies after cryptographic validation.
type ClaimRules struct {
	rejectActClaim bool
	allowedIssuers []string
	maxTokenAge    time.Duration
}

// ClaimRulesConfig holds claim rule settings for a JWT validator.
type ClaimRulesConfig struct {
	// RejectActClaim rejects tokens that include an impersonation (act) claim.
	RejectActClaim bool

	// AllowedIssuers restricts the token iss claim. Empty disables enforcement.
	AllowedIssuers []string

	// MaxTokenAge rejects tokens whose iat is older than now - MaxTokenAge.
	// Zero disables enforcement.
	MaxTokenAge time.Duration
}

// NewClaimRules builds claim rules from configuration. Nil or empty config returns nil.
func NewClaimRules(cfg *ClaimRulesConfig) *ClaimRules {
	if cfg == nil {
		return nil
	}
	if !cfg.RejectActClaim && len(cfg.AllowedIssuers) == 0 && cfg.MaxTokenAge == 0 {
		return nil
	}
	return &ClaimRules{
		rejectActClaim: cfg.RejectActClaim,
		allowedIssuers: slices.Clone(cfg.AllowedIssuers),
		maxTokenAge:    cfg.MaxTokenAge,
	}
}

// Evaluate applies configured claim rules to a validated token.
func (r *ClaimRules) Evaluate(claims map[string]any, issuer string, issuedAt time.Time, now time.Time) error {
	if r == nil {
		return nil
	}

	if r.rejectActClaim {
		if act, ok := claims["act"]; ok && act != nil {
			return fmt.Errorf("%w: impersonation (act claim) not permitted", ErrForbiddenToken)
		}
	}

	if len(r.allowedIssuers) > 0 {
		if issuer == "" || !slices.Contains(r.allowedIssuers, issuer) {
			return fmt.Errorf("%w: issuer not in allowlist", ErrInvalidToken)
		}
	}

	if r.maxTokenAge > 0 {
		if issuedAt.IsZero() {
			return fmt.Errorf("%w: missing issued-at claim", ErrInvalidToken)
		}
		oldestValid := now.Add(-r.maxTokenAge)
		if issuedAt.Before(oldestValid) {
			return fmt.Errorf("%w: token issued-at exceeds max age", ErrInvalidToken)
		}
	}

	return nil
}
