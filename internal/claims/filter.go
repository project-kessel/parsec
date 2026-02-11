package claims

// ClaimsFilter defines which claims should be passed through from a credential
type ClaimsFilter interface {
	// Filter filters the claims, returning only those that should be passed through
	Filter(c Claims) Claims
}

// AllowListClaimsFilter only allows claims in the allow list
type AllowListClaimsFilter struct {
	allowedClaims map[string]bool
}

// NewAllowListClaimsFilter creates a new allow list filter
func NewAllowListClaimsFilter(allowedClaims []string) *AllowListClaimsFilter {
	allowed := make(map[string]bool, len(allowedClaims))
	for _, claim := range allowedClaims {
		allowed[claim] = true
	}
	return &AllowListClaimsFilter{
		allowedClaims: allowed,
	}
}

// Filter implements ClaimsFilter
func (f *AllowListClaimsFilter) Filter(c Claims) Claims {
	if c == nil {
		return nil
	}
	filtered := make(Claims)
	for key, value := range c {
		if f.allowedClaims[key] {
			filtered[key] = value
		}
	}
	return filtered
}

// DenyListClaimsFilter blocks claims in the deny list
type DenyListClaimsFilter struct {
	deniedClaims map[string]bool
}

// NewDenyListClaimsFilter creates a new deny list filter
func NewDenyListClaimsFilter(deniedClaims []string) *DenyListClaimsFilter {
	denied := make(map[string]bool, len(deniedClaims))
	for _, claim := range deniedClaims {
		denied[claim] = true
	}
	return &DenyListClaimsFilter{
		deniedClaims: denied,
	}
}

// Filter implements ClaimsFilter
func (f *DenyListClaimsFilter) Filter(c Claims) Claims {
	if c == nil {
		return nil
	}
	filtered := make(Claims)
	for key, value := range c {
		if !f.deniedClaims[key] {
			filtered[key] = value
		}
	}
	return filtered
}

// PassthroughClaimsFilter passes all claims through
type PassthroughClaimsFilter struct{}

// Filter implements ClaimsFilter
func (f *PassthroughClaimsFilter) Filter(c Claims) Claims {
	return c.Copy()
}
