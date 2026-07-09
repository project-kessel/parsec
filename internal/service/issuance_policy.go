package service

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"reflect"
	"slices"

	"github.com/project-kessel/parsec/internal/trust"
)

// ErrIssuanceDenied is returned when an IssuancePolicy rejects token issuance.
var ErrIssuanceDenied = errors.New("issuance denied by policy")

// IssuancePolicy evaluates whether token issuance should proceed based on
// the authenticated subject's validated claims. This sits between credential
// validation (trust layer) and token issuance (service layer).
//
// Validators establish trust — they verify a credential is authentic and
// extract identity claims. IssuancePolicy decides whether those trusted
// claims are acceptable for token issuance.
type IssuancePolicy interface {
	Evaluate(ctx context.Context, subject *trust.Result) error
}

// NoOpIssuancePolicy always permits issuance.
type NoOpIssuancePolicy struct{}

func (NoOpIssuancePolicy) Evaluate(context.Context, *trust.Result) error { return nil }

// ClaimAssertionPolicy rejects issuance when the subject's validated claims
// fail configurable presence or value assertions. Claim names come from
// configuration — no vendor-specific logic is embedded.
type ClaimAssertionPolicy struct {
	requiredClaims []string
	rejectedClaims map[string]any
}

// NewClaimAssertionPolicy creates a policy that evaluates claim assertions.
// requiredClaims lists claim names that must be present in the subject's claims.
// rejectedClaims maps claim names to values that, if matched, cause rejection.
// Both may be nil/empty for no enforcement.
func NewClaimAssertionPolicy(requiredClaims []string, rejectedClaims map[string]any) *ClaimAssertionPolicy {
	return &ClaimAssertionPolicy{
		requiredClaims: slices.Clone(requiredClaims),
		rejectedClaims: maps.Clone(rejectedClaims),
	}
}

func (p *ClaimAssertionPolicy) Evaluate(_ context.Context, subject *trust.Result) error {
	if subject == nil {
		return nil
	}

	for claim, rejectedValue := range p.rejectedClaims {
		if val, ok := subject.Claims[claim]; ok && claimValuesEqual(val, rejectedValue) {
			return fmt.Errorf("%w: claim %q has rejected value", ErrIssuanceDenied, claim)
		}
	}

	for _, claim := range p.requiredClaims {
		if _, ok := subject.Claims[claim]; !ok {
			return fmt.Errorf("%w: required claim %q not present", ErrIssuanceDenied, claim)
		}
	}

	return nil
}

// claimValuesEqual compares two claim values, normalizing numeric types so
// that JSON-decoded float64 values match YAML-decoded int/int64 values.
func claimValuesEqual(a, b any) bool {
	fa, aIsNum := toFloat64(a)
	fb, bIsNum := toFloat64(b)
	if aIsNum && bIsNum {
		return fa == fb
	}
	return reflect.DeepEqual(a, b)
}

func toFloat64(v any) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	default:
		return 0, false
	}
}
