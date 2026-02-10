package service

import (
	"context"
	"strings"
	"testing"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/trust"
)

// FakeObserver is a test double that implements ApplicationObserver.
// It records all probe creations for later assertion in tests.
type FakeObserver struct {
	t *testing.T

	// All probes created across all observer methods
	Probes []*FakeProbe
}

// NewFakeObserver creates a new fake observer for testing
func NewFakeObserver(t *testing.T) *FakeObserver {
	return &FakeObserver{t: t, Probes: []*FakeProbe{}}
}

// TokenIssuanceStarted implements TokenServiceObserver
func (o *FakeObserver) TokenIssuanceStarted(
	ctx context.Context,
	subject *trust.Result,
	actor *trust.Result,
	scope string,
	tokenTypes []TokenType,
) (context.Context, TokenIssuanceProbe) {
	probe := &FakeProbe{
		t:           o.t,
		StartMethod: "TokenIssuanceStarted",
		StartArgs: map[string]any{
			"subject":    subject,
			"actor":      actor,
			"scope":      scope,
			"tokenTypes": tokenTypes,
		},
		calls: []probeCall{},
	}
	o.Probes = append(o.Probes, probe)
	return ctx, probe
}

// TokenExchangeStarted implements TokenExchangeObserver
func (o *FakeObserver) TokenExchangeStarted(
	ctx context.Context,
	grantType string,
	requestedTokenType string,
	audience string,
	scope string,
) (context.Context, TokenExchangeProbe) {
	probe := &FakeProbe{
		t:           o.t,
		StartMethod: "TokenExchangeStarted",
		StartArgs: map[string]any{
			"grantType":          grantType,
			"requestedTokenType": requestedTokenType,
			"audience":           audience,
			"scope":              scope,
		},
		calls: []probeCall{},
	}
	o.Probes = append(o.Probes, probe)
	return ctx, probe
}

// AuthzCheckStarted implements AuthzCheckObserver
func (o *FakeObserver) AuthzCheckStarted(
	ctx context.Context,
) (context.Context, AuthzCheckProbe) {
	probe := &FakeProbe{
		t:           o.t,
		StartMethod: "AuthzCheckStarted",
		StartArgs:   map[string]any{},
		calls:       []probeCall{},
	}
	o.Probes = append(o.Probes, probe)
	return ctx, probe
}

// AssertProbeCount verifies the expected number of probes were created
func (o *FakeObserver) AssertProbeCount(expected int) {
	o.t.Helper()
	if len(o.Probes) != expected {
		o.t.Errorf("expected %d probe(s), got %d", expected, len(o.Probes))
	}
}

// GetProbe returns the probe at the given index (0-based)
func (o *FakeObserver) GetProbe(index int) *FakeProbe {
	o.t.Helper()
	if index < 0 || index >= len(o.Probes) {
		o.t.Fatalf("probe index %d out of range (have %d probes)", index, len(o.Probes))
		return nil
	}
	return o.Probes[index]
}

// AssertSingleProbe asserts that exactly one probe was created with the given start method.
// Optionally checks start arguments if provided (pass nil values to skip checking).
// Returns the probe for further sequence assertions.
func (o *FakeObserver) AssertSingleProbe(startMethod string, args map[string]any) *FakeProbe {
	o.t.Helper()

	o.AssertProbeCount(1)
	if len(o.Probes) == 0 {
		return nil // AssertProbeCount already failed
	}

	probe := o.Probes[0]

	if probe.StartMethod != startMethod {
		o.t.Errorf("expected probe started with %s, got %s", startMethod, probe.StartMethod)
	}

	// Check provided start arguments
	for key, expectedVal := range args {
		if expectedVal == nil {
			continue // Skip nil checks
		}
		actualVal, ok := probe.StartArgs[key]
		if !ok {
			o.t.Errorf("probe missing start arg %q", key)
			continue
		}
		if actualVal != expectedVal {
			o.t.Errorf("probe start arg %q: expected %v, got %v", key, expectedVal, actualVal)
		}
	}

	return probe
}

// FakeProbe implements all probe interfaces and records method calls
type FakeProbe struct {
	t *testing.T

	// Captured at probe creation (exported for test assertions)
	StartMethod string
	StartArgs   map[string]any

	// Recorded method calls
	calls []probeCall
}

type probeCall struct {
	methodName string
	args       []any
}

func (p *probeCall) method() string {
	return p.methodName
}

func (p *probeCall) arguments() []any {
	return p.args
}

// recordCall records a method call
func (p *FakeProbe) recordCall(method string, args ...any) {
	p.calls = append(p.calls, probeCall{
		methodName: method,
		args:       args,
	})
}

// TokenIssuanceProbe methods
func (p *FakeProbe) TokenTypeIssuanceStarted(tokenType TokenType) {
	p.recordCall("TokenTypeIssuanceStarted", tokenType)
}

func (p *FakeProbe) TokenTypeIssuanceSucceeded(tokenType TokenType, token *Token) {
	p.recordCall("TokenTypeIssuanceSucceeded", tokenType, token)
}

func (p *FakeProbe) TokenTypeIssuanceFailed(tokenType TokenType, err error) {
	p.recordCall("TokenTypeIssuanceFailed", tokenType, err)
}

func (p *FakeProbe) IssuerNotFound(tokenType TokenType, err error) {
	p.recordCall("IssuerNotFound", tokenType, err)
}

// TokenExchangeProbe methods
func (p *FakeProbe) ActorValidationSucceeded(actor *trust.Result) {
	p.recordCall("ActorValidationSucceeded", actor)
}

func (p *FakeProbe) ActorValidationFailed(err error) {
	p.recordCall("ActorValidationFailed", err)
}

func (p *FakeProbe) RequestContextParsed(attrs *request.RequestAttributes) {
	p.recordCall("RequestContextParsed", attrs)
}

func (p *FakeProbe) RequestContextParseFailed(err error) {
	p.recordCall("RequestContextParseFailed", err)
}

func (p *FakeProbe) SubjectTokenValidationSucceeded(subject *trust.Result) {
	p.recordCall("SubjectTokenValidationSucceeded", subject)
}

func (p *FakeProbe) SubjectTokenValidationFailed(err error) {
	p.recordCall("SubjectTokenValidationFailed", err)
}

// AuthzCheckProbe methods
func (p *FakeProbe) RequestAttributesParsed(attrs *request.RequestAttributes) {
	p.recordCall("RequestAttributesParsed", attrs)
}

func (p *FakeProbe) SubjectCredentialExtracted(cred trust.Credential, headersUsed []string) {
	p.recordCall("SubjectCredentialExtracted", cred, headersUsed)
}

func (p *FakeProbe) SubjectCredentialExtractionFailed(err error) {
	p.recordCall("SubjectCredentialExtractionFailed", err)
}

func (p *FakeProbe) SubjectValidationSucceeded(subject *trust.Result) {
	p.recordCall("SubjectValidationSucceeded", subject)
}

func (p *FakeProbe) SubjectValidationFailed(err error) {
	p.recordCall("SubjectValidationFailed", err)
}

// End is common to all probes
func (p *FakeProbe) End() {
	p.recordCall("End")
}

// AssertProbeSequence verifies the exact sequence of probe method calls.
// Accepts either strings (method names) or ProbeMatcher functions.
func (p *FakeProbe) AssertProbeSequence(expected ...any) {
	p.t.Helper()
	if len(p.calls) != len(expected) {
		p.t.Errorf("expected %d probe calls, got %d", len(expected), len(p.calls))
		p.t.Logf("actual probe calls: %v", p.methodNames())
		return
	}
	for i, exp := range expected {
		call := p.calls[i]
		switch e := exp.(type) {
		case string:
			// Simple method name matching
			if call.method() != e {
				p.t.Errorf("probe call %d: expected method %s, got %s", i, e, call.method())
			}
		case ProbeMatcher:
			// Custom matcher function
			if !e(call) {
				p.t.Errorf("probe call %d: matcher failed for %s", i, call.method())
			}
		default:
			p.t.Errorf("invalid expected type at position %d: %T", i, exp)
		}
	}
}

func (p *FakeProbe) methodNames() []string {
	names := make([]string, len(p.calls))
	for i, call := range p.calls {
		names[i] = call.method()
	}
	return names
}

// ProbeMatcher is a function that matches against a probe call
type ProbeMatcher func(probeCall) bool

// ProbeCall creates a matcher that checks probe method name and optionally arguments.
// Arguments can be either concrete values (checked with ==) or ArgumentMatcher instances.
func ProbeCall(method string, args ...any) ProbeMatcher {
	return func(call probeCall) bool {
		if call.method() != method {
			return false
		}
		if len(args) == 0 {
			return true // Just matching method name
		}
		callArgs := call.arguments()
		if len(args) != len(callArgs) {
			return false
		}
		for i, expected := range args {
			// Check if expected is an ArgumentMatcher
			if matcher, ok := expected.(ArgumentMatcher); ok {
				if !matcher.Matches(callArgs[i]) {
					return false
				}
			} else {
				// Direct equality comparison
				if expected != callArgs[i] {
					return false
				}
			}
		}
		return true
	}
}

// ArgumentMatcher allows flexible matching of probe arguments
type ArgumentMatcher interface {
	Matches(actual any) bool
}

// ErrorContaining creates a matcher that checks if an error's message contains a substring
type ErrorContaining string

func (e ErrorContaining) Matches(actual any) bool {
	err, ok := actual.(error)
	if !ok || err == nil {
		return false
	}
	return strings.Contains(err.Error(), string(e))
}

// AnyError matches any non-nil error
type anyErrorMatcher struct{}

// AnyError returns a matcher that matches any non-nil error
func AnyError() ArgumentMatcher {
	return anyErrorMatcher{}
}

func (anyErrorMatcher) Matches(actual any) bool {
	err, ok := actual.(error)
	return ok && err != nil
}
