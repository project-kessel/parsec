package lua

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/project-kessel/parsec/internal/httpclient"
)

// redirectServers returns an upstream that redirects /start to target+"/steal"
// (or to its own /final when sameOrigin), and a counter of target hits.
func redirectServers(t *testing.T, sameOrigin bool) (upstream string, targetHits *atomic.Int32) {
	t.Helper()
	targetHits = &atomic.Int32{}
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		targetHits.Add(1)
		_, _ = w.Write([]byte("stolen"))
	}))
	t.Cleanup(target.Close)

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			_, _ = w.Write([]byte("final"))
			return
		}
		dest := target.URL + "/steal"
		if sameOrigin {
			dest = "/final"
		}
		http.Redirect(w, r, dest, http.StatusFound)
	}))
	t.Cleanup(up.Close)
	return up.URL, targetHits
}

func headerOptions(req *http.Request) error {
	req.Header.Set("Authorization", "Bearer s3cret")
	req.Header.Set("X-Rh-Apitoken", "s3cret")
	return nil
}

func TestHTTPService_RequestOptionsRefusesCrossOriginRedirect(t *testing.T) {
	upstream, hits := redirectServers(t, false)

	svc, err := NewHTTPService(context.Background(), &http.Client{}, WithRequestOptions(headerOptions))
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}

	got := runLuaHTTP(t, svc, resultScript(`http.get("`+upstream+`/start")`))
	if !strings.Contains(got, httpclient.ErrCrossOriginRedirect.Error()) {
		t.Errorf("result = %q, want cross-origin redirect error", got)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("redirect target received %d requests, want 0", n)
	}
}

func TestHTTPService_RequestOptionsFollowsSameOriginRedirect(t *testing.T) {
	upstream, _ := redirectServers(t, true)

	svc, err := NewHTTPService(context.Background(), &http.Client{}, WithRequestOptions(headerOptions))
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}

	if got := runLuaHTTP(t, svc, resultScript(`http.get("`+upstream+`/start")`)); got != "ok:5" {
		t.Errorf("result = %q, want ok:5 (body \"final\")", got)
	}
}

func TestHTTPService_CredentialTransportOutsideRegistryRefusesCrossOriginRedirect(t *testing.T) {
	upstream, hits := redirectServers(t, false)

	// Hand-built client without the registry's redirect policy.
	client := &http.Client{Transport: &httpclient.BearerTransport{Token: "s3cret", Base: http.DefaultTransport}}
	svc, err := NewHTTPService(context.Background(), client)
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}

	got := runLuaHTTP(t, svc, resultScript(`http.get("`+upstream+`/start")`))
	if !strings.Contains(got, httpclient.ErrCrossOriginRedirect.Error()) {
		t.Errorf("result = %q, want cross-origin redirect error", got)
	}
	if n := hits.Load(); n != 0 {
		t.Errorf("redirect target received %d requests, want 0", n)
	}
}

func TestHTTPService_UnauthenticatedClientFollowsCrossOriginRedirect(t *testing.T) {
	upstream, hits := redirectServers(t, false)

	svc, err := NewHTTPService(context.Background(), &http.Client{})
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}

	if got := runLuaHTTP(t, svc, resultScript(`http.get("`+upstream+`/start")`)); got != "ok:6" {
		t.Errorf("result = %q, want ok:6 (body \"stolen\")", got)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("redirect target received %d requests, want 1", n)
	}
}

func TestHTTPService_RequestOptionsRefusesRedirectHTTPSDowngrade(t *testing.T) {
	var plainHits atomic.Int32
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		plainHits.Add(1)
		_, _ = w.Write([]byte("plaintext"))
	}))
	defer plain.Close()

	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, plain.URL+"/steal", http.StatusFound)
	}))
	defer secure.Close()

	svc, err := NewHTTPService(context.Background(), secure.Client(), WithRequestOptions(headerOptions))
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}

	got := runLuaHTTP(t, svc, resultScript(`http.get("`+secure.URL+`/start")`))
	if !strings.Contains(got, httpclient.ErrCrossOriginRedirect.Error()) {
		t.Errorf("result = %q, want cross-origin redirect error", got)
	}
	if n := plainHits.Load(); n != 0 {
		t.Errorf("plain http target received %d requests, want 0", n)
	}
}

func TestHTTPService_RedirectPolicyKeepsAndDoesNotMutateCallerPolicy(t *testing.T) {
	errCustom := errors.New("custom policy")
	var customCalls atomic.Int32
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error {
		customCalls.Add(1)
		return errCustom
	}}

	upstream, _ := redirectServers(t, true)
	svc, err := NewHTTPService(context.Background(), client, WithRequestOptions(headerOptions))
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}

	// The caller's existing policy still runs for same-origin hops.
	got := runLuaHTTP(t, svc, resultScript(`http.get("`+upstream+`/start")`))
	if !strings.Contains(got, errCustom.Error()) {
		t.Errorf("result = %q, want caller's custom policy error", got)
	}
	if n := customCalls.Load(); n != 1 {
		t.Errorf("custom policy calls = %d, want 1", n)
	}

	// The caller's client keeps its own policy, not the wrapped one: a
	// cross-origin hop reaches the custom policy directly.
	from := httptestRequest(t, "https://api.example.com/a")
	to := httptestRequest(t, "https://evil.example.net/b")
	if err := client.CheckRedirect(to, []*http.Request{from}); !errors.Is(err, errCustom) {
		t.Errorf("caller CheckRedirect returned %v, want the original custom policy", err)
	}
}

func httptestRequest(t *testing.T, raw string) *http.Request {
	t.Helper()
	req, err := http.NewRequest(http.MethodGet, raw, nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	return req
}
