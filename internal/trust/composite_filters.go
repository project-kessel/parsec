package trust

import (
	"fmt"
	"strings"

	"github.com/project-kessel/parsec/internal/request"
)

// AnyValidatorFilter composes multiple filters and returns true if any of them return true
type AnyValidatorFilter struct {
	filters []ValidatorFilter
}

// NewAnyValidatorFilter creates a new composite filter that returns true if any sub-filter returns true
func NewAnyValidatorFilter(filters ...ValidatorFilter) *AnyValidatorFilter {
	return &AnyValidatorFilter{
		filters: filters,
	}
}

// IsAllowed implements the ValidatorFilter interface
// Returns true if ANY of the sub-filters return true
// Returns false only if ALL filters return false or error
func (f *AnyValidatorFilter) IsAllowed(actor *Result, validatorName string, requestAttrs *request.RequestAttributes) (bool, error) {
	if len(f.filters) == 0 {
		return false, fmt.Errorf("no filters configured")
	}

	var errors []string
	for i, filter := range f.filters {
		allowed, err := filter.IsAllowed(actor, validatorName, requestAttrs)
		if err != nil {
			errors = append(errors, fmt.Sprintf("filter %d: %v", i, err))
			continue
		}

		if allowed {
			return true, nil
		}
	}

	// All filters returned false or errored
	if len(errors) > 0 {
		return false, fmt.Errorf("all filters failed: %s", strings.Join(errors, "; "))
	}

	return false, nil
}
