package observer

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"

	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/httpclient"
	"github.com/project-kessel/parsec/internal/keys"
	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// TestCompositeAuthzCheckProbe_FansOutAllMethods exercises every method on
// compositeAuthzCheckProbe to verify that each call reaches both children.
// This is the highest-value composite test: authz check probes carry the
// audit events that must never be silently dropped.
func TestCompositeAuthzCheckProbe_FansOutAllMethods(t *testing.T) {
	var c1, c2 authzProbeCalls

	composite := &compositeAuthzCheckProbe{
		probes: []service.AuthzCheckProbe{
			&trackingAuthzProbe{c: &c1},
			&trackingAuthzProbe{c: &c2},
		},
	}

	composite.RequestAttributesParsed(&request.RequestAttributes{Method: "GET", Path: "/test"})
	composite.ActorCredentialExtracted(nil, nil)
	composite.ActorCredentialExtractionFailed(errors.New("test"))
	composite.ActorValidationSucceeded(nil)
	composite.ActorValidationFailed(errors.New("test"))
	composite.SubjectCredentialExtracted(nil, nil)
	composite.SubjectCredentialExtractionFailed(errors.New("test"))
	composite.SubjectValidationSucceeded(nil)
	composite.SubjectValidationFailed(errors.New("test"))
	composite.SubjectAnonymous()
	composite.PolicyDecisionIssue(2, "scope", "reason")
	composite.PolicyDecisionAllowWithoutIssue("reason")
	composite.PolicyDecisionDeny("denied")
	composite.PolicyEvaluationFailed(errors.New("eval"))
	composite.TokenIssuanceFailed(errors.New("issuance"))
	composite.End()

	for _, tc := range []struct {
		name   string
		v1, v2 *atomic.Int32
	}{
		{"RequestAttributesParsed", &c1.requestAttrsParsed, &c2.requestAttrsParsed},
		{"ActorCredentialExtracted", &c1.actorCredentialExtracted, &c2.actorCredentialExtracted},
		{"ActorCredentialExtractionFailed", &c1.actorCredentialExtrFail, &c2.actorCredentialExtrFail},
		{"ActorValidationSucceeded", &c1.actorValidationSucceeded, &c2.actorValidationSucceeded},
		{"ActorValidationFailed", &c1.actorValidationFailed, &c2.actorValidationFailed},
		{"SubjectCredentialExtracted", &c1.subjectCredentialExtracted, &c2.subjectCredentialExtracted},
		{"SubjectCredentialExtractionFailed", &c1.subjectCredentialExtrFail, &c2.subjectCredentialExtrFail},
		{"SubjectValidationSucceeded", &c1.subjectValidationSucceeded, &c2.subjectValidationSucceeded},
		{"SubjectValidationFailed", &c1.subjectValidationFailed, &c2.subjectValidationFailed},
		{"SubjectAnonymous", &c1.subjectAnonymous, &c2.subjectAnonymous},
		{"PolicyDecisionIssue", &c1.policyDecisionIssue, &c2.policyDecisionIssue},
		{"PolicyDecisionAllowWithoutIssue", &c1.policyDecisionAllow, &c2.policyDecisionAllow},
		{"PolicyDecisionDeny", &c1.policyDecisionDeny, &c2.policyDecisionDeny},
		{"PolicyEvaluationFailed", &c1.policyEvaluationFailed, &c2.policyEvaluationFailed},
		{"TokenIssuanceFailed", &c1.tokenIssuanceFailed, &c2.tokenIssuanceFailed},
		{"End", &c1.end, &c2.end},
	} {
		if tc.v1.Load() != 1 {
			t.Errorf("%s: child1 expected 1 call, got %d", tc.name, tc.v1.Load())
		}
		if tc.v2.Load() != 1 {
			t.Errorf("%s: child2 expected 1 call, got %d", tc.name, tc.v2.Load())
		}
	}
}

// TestCompositeStopProbe_FansOutAllMethods verifies the stop probe
// fan-out, which carries the shutdown audit events.
func TestCompositeStopProbe_FansOutAllMethods(t *testing.T) {
	var completed1, completed2 atomic.Int32
	var failed1, failed2 atomic.Int32
	var end1, end2 atomic.Int32

	composite := &compositeStopProbe{
		probes: []server.StopProbe{
			&trackingStopProbe{completed: &completed1, failed: &failed1, ended: &end1},
			&trackingStopProbe{completed: &completed2, failed: &failed2, ended: &end2},
		},
	}

	composite.ShutdownCompleted(5)
	composite.ShutdownFailed(3)
	composite.End()

	for _, tc := range []struct {
		name   string
		v1, v2 *atomic.Int32
	}{
		{"ShutdownCompleted", &completed1, &completed2},
		{"ShutdownFailed", &failed1, &failed2},
		{"End", &end1, &end2},
	} {
		if tc.v1.Load() != 1 {
			t.Errorf("%s: child1 expected 1 call, got %d", tc.name, tc.v1.Load())
		}
		if tc.v2.Load() != 1 {
			t.Errorf("%s: child2 expected 1 call, got %d", tc.name, tc.v2.Load())
		}
	}
}

// TestCompositeTokenExchangeProbe_FansOutAllMethods verifies the token
// exchange probe fan-out for audit event completeness.
func TestCompositeTokenExchangeProbe_FansOutAllMethods(t *testing.T) {
	var c1, c2 tokenExchangeProbeCalls

	composite := &compositeTokenExchangeProbe{
		probes: []service.TokenExchangeProbe{
			&trackingTokenExchangeProbe{c: &c1},
			&trackingTokenExchangeProbe{c: &c2},
		},
	}

	composite.ActorCredentialExtracted(nil, nil)
	composite.ActorCredentialExtractionFailed(errors.New("test"))
	composite.ActorValidationSucceeded(nil)
	composite.ActorValidationFailed(errors.New("test"))
	composite.RequestContextParsed(nil)
	composite.RequestContextParseFailed(errors.New("test"))
	composite.SubjectTokenValidationSucceeded(nil)
	composite.SubjectTokenValidationFailed(errors.New("test"))
	composite.TokenIssuanceFailed(errors.New("issuance"))
	composite.RequestFailed(errors.New("request"))
	composite.End()

	for _, tc := range []struct {
		name   string
		v1, v2 *atomic.Int32
	}{
		{"ActorCredentialExtracted", &c1.actorCredExtracted, &c2.actorCredExtracted},
		{"ActorCredentialExtractionFailed", &c1.actorCredExtrFail, &c2.actorCredExtrFail},
		{"ActorValidationSucceeded", &c1.actorValSucceeded, &c2.actorValSucceeded},
		{"ActorValidationFailed", &c1.actorValFailed, &c2.actorValFailed},
		{"RequestContextParsed", &c1.reqCtxParsed, &c2.reqCtxParsed},
		{"RequestContextParseFailed", &c1.reqCtxParseFail, &c2.reqCtxParseFail},
		{"SubjectTokenValidationSucceeded", &c1.subjectTokenValSuccess, &c2.subjectTokenValSuccess},
		{"SubjectTokenValidationFailed", &c1.subjectTokenValFail, &c2.subjectTokenValFail},
		{"TokenIssuanceFailed", &c1.tokenIssuanceFailed, &c2.tokenIssuanceFailed},
		{"RequestFailed", &c1.requestFailed, &c2.requestFailed},
		{"End", &c1.end, &c2.end},
	} {
		if tc.v1.Load() != 1 {
			t.Errorf("%s: child1 expected 1 call, got %d", tc.name, tc.v1.Load())
		}
		if tc.v2.Load() != 1 {
			t.Errorf("%s: child2 expected 1 call, got %d", tc.name, tc.v2.Load())
		}
	}
}

// TestCompositeAll_GRPCAndHTTPServeFailed_FansOut exercises the non-probe
// lifecycle event fan-out methods.
func TestCompositeAll_GRPCAndHTTPServeFailed_FansOut(t *testing.T) {
	var grpc1, grpc2, http1, http2, ready1, ready2 atomic.Int32

	child1 := Compose(
		service.NoOpServiceObserver{},
		datasource.NoOpDataSourceObserver{},
		keys.NoOpKeysObserver{},
		trust.NoOpTrustObserver{},
		&trackingLifecycleObserver{grpcFailed: &grpc1, httpFailed: &http1, processReady: &ready1},
		httpclient.NoOpHTTPClientObserver{},
	)
	child2 := Compose(
		service.NoOpServiceObserver{},
		datasource.NoOpDataSourceObserver{},
		keys.NoOpKeysObserver{},
		trust.NoOpTrustObserver{},
		&trackingLifecycleObserver{grpcFailed: &grpc2, httpFailed: &http2, processReady: &ready2},
		httpclient.NoOpHTTPClientObserver{},
	)

	composite := CompositeAll([]Observer{child1, child2})
	composite.GRPCServeFailed(errors.New("bind failed"))
	composite.HTTPServeFailed(errors.New("bind failed"))
	composite.ProcessReady(server.ProcessInfo{Version: "v1"})

	for _, tc := range []struct {
		name   string
		v1, v2 *atomic.Int32
	}{
		{"GRPCServeFailed", &grpc1, &grpc2},
		{"HTTPServeFailed", &http1, &http2},
		{"ProcessReady", &ready1, &ready2},
	} {
		if tc.v1.Load() != 1 {
			t.Errorf("%s: child1 expected 1, got %d", tc.name, tc.v1.Load())
		}
		if tc.v2.Load() != 1 {
			t.Errorf("%s: child2 expected 1, got %d", tc.name, tc.v2.Load())
		}
	}
}

// --- tracking spy types ---

type authzProbeCalls struct {
	requestAttrsParsed         atomic.Int32
	actorCredentialExtracted   atomic.Int32
	actorCredentialExtrFail    atomic.Int32
	actorValidationSucceeded   atomic.Int32
	actorValidationFailed      atomic.Int32
	subjectCredentialExtracted atomic.Int32
	subjectCredentialExtrFail  atomic.Int32
	subjectValidationSucceeded atomic.Int32
	subjectValidationFailed    atomic.Int32
	subjectAnonymous           atomic.Int32
	policyDecisionIssue        atomic.Int32
	policyDecisionAllow        atomic.Int32
	policyDecisionDeny         atomic.Int32
	policyEvaluationFailed     atomic.Int32
	tokenIssuanceFailed        atomic.Int32
	end                        atomic.Int32
}

type trackingAuthzProbe struct {
	c *authzProbeCalls
}

func (p *trackingAuthzProbe) RequestAttributesParsed(*request.RequestAttributes) {
	p.c.requestAttrsParsed.Add(1)
}
func (p *trackingAuthzProbe) ActorCredentialExtracted(trust.Credential, []string) {
	p.c.actorCredentialExtracted.Add(1)
}
func (p *trackingAuthzProbe) ActorCredentialExtractionFailed(error) {
	p.c.actorCredentialExtrFail.Add(1)
}
func (p *trackingAuthzProbe) ActorValidationSucceeded(*trust.Result) {
	p.c.actorValidationSucceeded.Add(1)
}
func (p *trackingAuthzProbe) ActorValidationFailed(error) {
	p.c.actorValidationFailed.Add(1)
}
func (p *trackingAuthzProbe) SubjectCredentialExtracted(trust.Credential, []string) {
	p.c.subjectCredentialExtracted.Add(1)
}
func (p *trackingAuthzProbe) SubjectCredentialExtractionFailed(error) {
	p.c.subjectCredentialExtrFail.Add(1)
}
func (p *trackingAuthzProbe) SubjectValidationSucceeded(*trust.Result) {
	p.c.subjectValidationSucceeded.Add(1)
}
func (p *trackingAuthzProbe) SubjectValidationFailed(error) {
	p.c.subjectValidationFailed.Add(1)
}
func (p *trackingAuthzProbe) SubjectAnonymous()                       { p.c.subjectAnonymous.Add(1) }
func (p *trackingAuthzProbe) PolicyDecisionIssue(int, string, string) { p.c.policyDecisionIssue.Add(1) }
func (p *trackingAuthzProbe) PolicyDecisionAllowWithoutIssue(string)  { p.c.policyDecisionAllow.Add(1) }
func (p *trackingAuthzProbe) PolicyDecisionDeny(string)               { p.c.policyDecisionDeny.Add(1) }
func (p *trackingAuthzProbe) PolicyEvaluationFailed(error)            { p.c.policyEvaluationFailed.Add(1) }
func (p *trackingAuthzProbe) TokenIssuanceFailed(error)               { p.c.tokenIssuanceFailed.Add(1) }
func (p *trackingAuthzProbe) End()                                    { p.c.end.Add(1) }

type trackingStopProbe struct {
	completed *atomic.Int32
	failed    *atomic.Int32
	ended     *atomic.Int32
}

func (p *trackingStopProbe) ShutdownCompleted(int64) { p.completed.Add(1) }
func (p *trackingStopProbe) ShutdownFailed(int64)    { p.failed.Add(1) }
func (p *trackingStopProbe) End()                    { p.ended.Add(1) }

type tokenExchangeProbeCalls struct {
	actorCredExtracted     atomic.Int32
	actorCredExtrFail      atomic.Int32
	actorValSucceeded      atomic.Int32
	actorValFailed         atomic.Int32
	reqCtxParsed           atomic.Int32
	reqCtxParseFail        atomic.Int32
	subjectTokenValSuccess atomic.Int32
	subjectTokenValFail    atomic.Int32
	tokenIssuanceFailed    atomic.Int32
	requestFailed          atomic.Int32
	end                    atomic.Int32
}

type trackingTokenExchangeProbe struct {
	c *tokenExchangeProbeCalls
}

func (p *trackingTokenExchangeProbe) ActorCredentialExtracted(trust.Credential, []string) {
	p.c.actorCredExtracted.Add(1)
}
func (p *trackingTokenExchangeProbe) ActorCredentialExtractionFailed(error) {
	p.c.actorCredExtrFail.Add(1)
}
func (p *trackingTokenExchangeProbe) ActorValidationSucceeded(*trust.Result) {
	p.c.actorValSucceeded.Add(1)
}
func (p *trackingTokenExchangeProbe) ActorValidationFailed(error) {
	p.c.actorValFailed.Add(1)
}
func (p *trackingTokenExchangeProbe) RequestContextParsed(*request.RequestAttributes) {
	p.c.reqCtxParsed.Add(1)
}
func (p *trackingTokenExchangeProbe) RequestContextParseFailed(error) {
	p.c.reqCtxParseFail.Add(1)
}
func (p *trackingTokenExchangeProbe) SubjectTokenValidationSucceeded(*trust.Result) {
	p.c.subjectTokenValSuccess.Add(1)
}
func (p *trackingTokenExchangeProbe) SubjectTokenValidationFailed(error) {
	p.c.subjectTokenValFail.Add(1)
}
func (p *trackingTokenExchangeProbe) TokenIssuanceFailed(error) {
	p.c.tokenIssuanceFailed.Add(1)
}
func (p *trackingTokenExchangeProbe) RequestFailed(error) {
	p.c.requestFailed.Add(1)
}
func (p *trackingTokenExchangeProbe) End() { p.c.end.Add(1) }

type trackingLifecycleObserver struct {
	server.NoOpLifecycleObserver
	server.NoOpJWKSObserver
	grpcFailed   *atomic.Int32
	httpFailed   *atomic.Int32
	processReady *atomic.Int32
}

func (o *trackingLifecycleObserver) GRPCServeFailed(error)           { o.grpcFailed.Add(1) }
func (o *trackingLifecycleObserver) HTTPServeFailed(error)           { o.httpFailed.Add(1) }
func (o *trackingLifecycleObserver) ProcessReady(server.ProcessInfo) { o.processReady.Add(1) }
func (o *trackingLifecycleObserver) StopStarted(ctx context.Context) (context.Context, server.StopProbe) {
	return ctx, server.NoOpStopProbe{}
}
