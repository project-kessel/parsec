package scripts_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/project-kessel/parsec/internal/httpclient"
	"github.com/project-kessel/parsec/internal/httpfixture"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/trust"
)

const uhcCurrentAccountURL = "https://api.openshift.example.com/api/accounts_mgmt/v1/current_account"

func uhcLuaConfig() map[string]any {
	return map[string]any{
		"current_account_url": uhcCurrentAccountURL,
		"trust_domain":        "uhc.example.com",
		"issuer":              "uhc://api.openshift.example.com",
	}
}

func uhcAccountBody(t *testing.T, org map[string]any) string {
	t.Helper()
	b, err := json.Marshal(map[string]any{"organization": org})
	if err != nil {
		t.Fatalf("marshal account body: %v", err)
	}
	return string(b)
}

// uhcValidator builds the real validator over the real script, with OCM faked
// by the given provider.
func uhcValidator(t *testing.T, provider httpfixture.FixtureProvider) *trust.CacheableLuaValidator {
	t.Helper()
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: httpfixture.NewTransport(httpfixture.TransportConfig{
			Provider: provider,
			Strict:   true,
		}),
	}
	v, err := trust.NewCacheableLuaValidator(
		"uhc-auth",
		loadScript(t, "uhc_auth.lua"),
		[]trust.CredentialType{trust.CredentialTypeHeader},
		trust.WithLuaConfigSource(luaservices.NewMapConfigSource(uhcLuaConfig())),
		trust.WithLuaHTTP(httpclient.LuaClient{Client: client}),
	)
	if err != nil {
		t.Fatalf("NewCacheableLuaValidator: %v", err)
	}
	return v
}

// uhcOKProvider answers current_account with a 200 and the given organization.
func uhcOKProvider(t *testing.T, org map[string]any) httpfixture.FixtureProvider {
	t.Helper()
	return uhcProvider(t, 200, uhcAccountBody(t, org))
}

func uhcProvider(t *testing.T, status int, body string) httpfixture.FixtureProvider {
	t.Helper()
	return httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		if req.URL.String() != uhcCurrentAccountURL {
			return nil
		}
		return &httpfixture.Fixture{
			StatusCode: status,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       body,
		}
	})
}

func uhcCredential(userAgent, authorization string) *trust.HeaderCredential {
	return &trust.HeaderCredential{Headers: map[string]string{
		"user-agent":    userAgent,
		"authorization": authorization,
	}}
}

func TestUHCAuth_HappyPath(t *testing.T) {
	v := uhcValidator(t, uhcOKProvider(t, map[string]any{
		"external_id":     "12345",
		"ebs_account_id":  "540155",
		"id":              "org-internal-id",
		"name":            "Test Org",
		"unrelated_field": true,
	}))

	result, err := v.Validate(context.Background(), uhcCredential("insights-operator/abcdef cluster/1234321", "Bearer ocm-token"))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if result.Subject != "1234321" {
		t.Errorf("Subject=%q, want 1234321", result.Subject)
	}
	if result.Issuer != "uhc://api.openshift.example.com" {
		t.Errorf("Issuer=%q, want uhc://api.openshift.example.com", result.Issuer)
	}
	if result.TrustDomain != "uhc.example.com" {
		t.Errorf("TrustDomain=%q, want uhc.example.com", result.TrustDomain)
	}
	if got := result.Claims["org_id"]; got != "12345" {
		t.Errorf("org_id=%v, want 12345", got)
	}
	if got := result.Claims["cluster_id"]; got != "1234321" {
		t.Errorf("cluster_id=%v, want 1234321", got)
	}
	if got := result.Claims["account_number"]; got != "540155" {
		t.Errorf("account_number=%v, want 540155", got)
	}
}

// The custom AccessToken scheme is the detail most likely to regress: OCM does
// not accept a Bearer passthrough of the cluster token.
func TestUHCAuth_OutboundAuthorizationHeader(t *testing.T) {
	var gotAuthorization, gotAccept, gotContentType string
	provider := httpfixture.NewFuncProvider(func(req *http.Request) *httpfixture.Fixture {
		if req.URL.String() != uhcCurrentAccountURL {
			return nil
		}
		gotAuthorization = req.Header.Get("Authorization")
		gotAccept = req.Header.Get("Accept")
		gotContentType = req.Header.Get("Content-Type")
		return &httpfixture.Fixture{
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       uhcAccountBody(t, map[string]any{"external_id": "12345"}),
		}
	})

	v := uhcValidator(t, provider)
	if _, err := v.Validate(context.Background(), uhcCredential("insights-operator/abcdef cluster/1234321", "Bearer ocm-token")); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	if want := "AccessToken 1234321:ocm-token"; gotAuthorization != want {
		t.Errorf("Authorization=%q, want %q", gotAuthorization, want)
	}
	if gotAccept != "application/json" {
		t.Errorf("Accept=%q, want application/json", gotAccept)
	}
	if gotContentType != "application/json" {
		t.Errorf("Content-Type=%q, want application/json", gotContentType)
	}
}

func TestUHCAuth_AllowedOperatorPrefixes(t *testing.T) {
	prefixes := []string{
		"insights-operator",
		"cost-mgmt-operator",
		"marketplace-operator",
		"acm-operator",
		"assisted-installer-operator",
		"cryostat-operator",
		"openshift-lightspeed-operator",
		"jws-operator",
		"runtimes-inventory-operator",
	}

	for _, prefix := range prefixes {
		t.Run(prefix, func(t *testing.T) {
			v := uhcValidator(t, uhcOKProvider(t, map[string]any{"external_id": "12345"}))
			ua := fmt.Sprintf("%s/abcdef cluster/1234321", prefix)
			result, err := v.Validate(context.Background(), uhcCredential(ua, "Bearer ocm-token"))
			if err != nil {
				t.Fatalf("Validate: %v", err)
			}
			if result.Subject != "1234321" {
				t.Errorf("Subject=%q, want 1234321", result.Subject)
			}
		})
	}
}

// The credential source matches a loose "*-operator/... cluster/..." pattern;
// the script is what enforces the actual allowlist.
func TestUHCAuth_RejectsCredential(t *testing.T) {
	tests := []struct {
		name          string
		userAgent     string
		authorization string
	}{
		{name: "operator not on the allowlist", userAgent: "rogue-operator/abcdef cluster/1234321", authorization: "Bearer ocm-token"},
		{name: "prefix only matches at the start", userAgent: "evil-insights-operator/abcdef cluster/1234321", authorization: "Bearer ocm-token"},
		{name: "missing cluster segment", userAgent: "insights-operator/abcdef", authorization: "Bearer ocm-token"},
		{name: "cluster segment not prefixed", userAgent: "insights-operator/abcdef 1234321", authorization: "Bearer ocm-token"},
		{name: "empty cluster id", userAgent: "insights-operator/abcdef cluster/", authorization: "Bearer ocm-token"},
		{name: "empty user agent", userAgent: "", authorization: "Bearer ocm-token"},
		{name: "non-bearer scheme", userAgent: "insights-operator/abcdef cluster/1234321", authorization: "AccessToken 1234321:ocm-token"},
		{name: "blank bearer token", userAgent: "insights-operator/abcdef cluster/1234321", authorization: "Bearer "},
		{name: "empty authorization", userAgent: "insights-operator/abcdef cluster/1234321", authorization: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Strict transport: any outbound call here is itself a failure,
			// since none of these should reach OCM.
			v := uhcValidator(t, httpfixture.NewFuncProvider(func(*http.Request) *httpfixture.Fixture { return nil }))
			_, err := v.Validate(context.Background(), uhcCredential(tt.userAgent, tt.authorization))
			if !errors.Is(err, trust.ErrInvalidToken) {
				t.Fatalf("err=%v, want ErrInvalidToken", err)
			}
		})
	}
}

func TestUHCAuth_RejectsResponse(t *testing.T) {
	tests := []struct {
		name   string
		status int
		body   string
	}{
		{name: "unauthorized", status: 401, body: `{}`},
		{name: "forbidden", status: 403, body: `{}`},
		{name: "server error", status: 500, body: `{}`},
		{name: "malformed body", status: 200, body: `{not json`},
		{name: "organization absent", status: 200, body: `{}`},
		{name: "external_id missing", status: 200, body: `{"organization":{"ebs_account_id":"540155"}}`},
		{name: "external_id empty", status: 200, body: `{"organization":{"external_id":""}}`},
		{name: "external_id literal null string", status: 200, body: `{"organization":{"external_id":"null"}}`},
		{name: "external_id JSON null", status: 200, body: `{"organization":{"external_id":null}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			v := uhcValidator(t, uhcProvider(t, tt.status, tt.body))
			_, err := v.Validate(context.Background(), uhcCredential("insights-operator/abcdef cluster/1234321", "Bearer ocm-token"))
			if !errors.Is(err, trust.ErrInvalidToken) {
				t.Fatalf("err=%v, want ErrInvalidToken", err)
			}
		})
	}
}

// Organizations without an EBS account are legitimate; only org_id is required.
func TestUHCAuth_EmptyEBSAccountAllowed(t *testing.T) {
	v := uhcValidator(t, uhcOKProvider(t, map[string]any{
		"external_id":    "12345",
		"ebs_account_id": "",
	}))

	result, err := v.Validate(context.Background(), uhcCredential("insights-operator/abcdef cluster/1234321", "Bearer ocm-token"))
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}
	if _, ok := result.Claims["account_number"]; ok {
		t.Errorf("account_number should be absent, got %v", result.Claims["account_number"])
	}
	if got := result.Claims["org_id"]; got != "12345" {
		t.Errorf("org_id=%v, want 12345", got)
	}
}

// A transport failure is an outage, not a rejection, so it must surface as an
// error rather than a clean deny.
func TestUHCAuth_TransportFailureErrors(t *testing.T) {
	v := uhcValidator(t, httpfixture.NewFuncProvider(func(*http.Request) *httpfixture.Fixture { return nil }))

	_, err := v.Validate(context.Background(), uhcCredential("insights-operator/abcdef cluster/1234321", "Bearer ocm-token"))
	if err == nil {
		t.Fatal("expected an error")
	}
	if errors.Is(err, trust.ErrInvalidToken) {
		t.Fatalf("transport failure should not be a clean rejection: %v", err)
	}
}

func TestUHCAuth_CacheKey(t *testing.T) {
	v := uhcValidator(t, uhcOKProvider(t, map[string]any{"external_id": "12345"}))

	keyFor := func(t *testing.T, userAgent, authorization string) string {
		t.Helper()
		input, err := v.CacheKey(uhcCredential(userAgent, authorization))
		if err != nil {
			t.Fatalf("CacheKey: %v", err)
		}
		b, err := trust.MarshalCredentialJSON(input.Credential)
		if err != nil {
			t.Fatalf("MarshalCredentialJSON: %v", err)
		}
		return string(b)
	}

	base := keyFor(t, "insights-operator/abcdef cluster/1234321", "Bearer ocm-token")

	if repeat := keyFor(t, "insights-operator/abcdef cluster/1234321", "Bearer ocm-token"); repeat != base {
		t.Errorf("key is not stable: %q vs %q", base, repeat)
	}
	if other := keyFor(t, "insights-operator/abcdef cluster/9999999", "Bearer ocm-token"); other == base {
		t.Error("key must vary with the cluster id")
	}
	if other := keyFor(t, "insights-operator/abcdef cluster/1234321", "Bearer other-token"); other == base {
		t.Error("key must vary with the token")
	}
	if other := keyFor(t, "cost-mgmt-operator/abcdef cluster/1234321", "Bearer ocm-token"); other != base {
		t.Errorf("key must not vary with the operator: %q vs %q", base, other)
	}
	if other := keyFor(t, "insights-operator/999999 cluster/1234321", "Bearer ocm-token"); other != base {
		t.Errorf("key must not vary with the operator version: %q vs %q", base, other)
	}
}

// A distributed cache fills from the cache key alone, so the key must still be
// a credential validate() accepts, yielding the same result.
func TestUHCAuth_CacheKeyCredentialStillValidates(t *testing.T) {
	v := uhcValidator(t, uhcOKProvider(t, map[string]any{"external_id": "12345"}))
	cred := uhcCredential("insights-operator/abcdef cluster/1234321", "Bearer ocm-token")

	want, err := v.Validate(context.Background(), cred)
	if err != nil {
		t.Fatalf("Validate: %v", err)
	}

	input, err := v.CacheKey(cred)
	if err != nil {
		t.Fatalf("CacheKey: %v", err)
	}

	got, err := v.Validate(context.Background(), input.Credential)
	if err != nil {
		t.Fatalf("Validate(cache key credential): %v", err)
	}

	if got.Subject != want.Subject || got.Issuer != want.Issuer || got.TrustDomain != want.TrustDomain {
		t.Errorf("cache key credential validated differently: got %+v, want %+v", got, want)
	}
	if fmt.Sprint(got.Claims) != fmt.Sprint(want.Claims) {
		t.Errorf("claims = %v, want %v", got.Claims, want.Claims)
	}
}
