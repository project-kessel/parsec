package httpclient

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync/atomic"
	"testing"
)

func mustReq(t *testing.T, raw string) *http.Request {
	t.Helper()
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	return &http.Request{URL: u}
}

func TestSameOriginRedirectPolicy(t *testing.T) {
	tests := []struct {
		name    string
		from    string
		to      string
		wantErr bool
	}{
		{"same origin new path", "https://api.example.com/a", "https://api.example.com/b?x=1", false},
		{"explicit default https port", "https://api.example.com/a", "https://api.example.com:443/b", false},
		{"explicit default http port", "http://api.example.com:80/a", "http://api.example.com/b", false},
		{"host case-insensitive", "https://API.example.com/a", "https://api.EXAMPLE.com/b", false},
		{"scheme case-insensitive", "HTTPS://api.example.com/a", "https://api.example.com/b", false},
		{"different host", "https://api.example.com/a", "https://evil.example.net/steal", true},
		{"subdomain", "https://example.com/a", "https://api.example.com/a", true},
		{"different port", "https://api.example.com/a", "https://api.example.com:8443/a", true},
		{"https downgrade to http", "https://api.example.com/a", "http://api.example.com/a", true},
		{"http upgrade to https", "http://api.example.com/a", "https://api.example.com/a", true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := SameOriginRedirectPolicy(mustReq(t, tt.to), []*http.Request{mustReq(t, tt.from)})
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && !errors.Is(err, ErrCrossOriginRedirect) {
				t.Errorf("err = %v, want ErrCrossOriginRedirect", err)
			}
		})
	}
}

func TestSameOriginRedirectPolicy_ComparesAgainstOriginalRequest(t *testing.T) {
	// A chain that leaves the origin and comes back is still refused at the
	// first hop away from the original request.
	orig := mustReq(t, "https://api.example.com/a")
	away := mustReq(t, "https://evil.example.net/b")
	if err := SameOriginRedirectPolicy(away, []*http.Request{orig}); err == nil {
		t.Fatal("expected first cross-origin hop to be refused")
	}
	back := mustReq(t, "https://api.example.com/c")
	if err := SameOriginRedirectPolicy(back, []*http.Request{orig, away}); err != nil {
		t.Fatalf("hop back to the original origin should be allowed, got %v", err)
	}
}

func TestSameOriginRedirectPolicy_ErrorOmitsPathAndQuery(t *testing.T) {
	err := SameOriginRedirectPolicy(
		mustReq(t, "https://evil.example.net/steal?token=s3cret"),
		[]*http.Request{mustReq(t, "https://api.example.com/users/alice")},
	)
	if err == nil {
		t.Fatal("expected error")
	}
	want := ErrCrossOriginRedirect.Error() + ": https://api.example.com -> https://evil.example.net"
	if err.Error() != want {
		t.Errorf("err = %q, want %q", err.Error(), want)
	}
}

func TestSameOriginRedirectPolicy_RedirectLimit(t *testing.T) {
	via := make([]*http.Request, maxRedirects)
	for i := range via {
		via[i] = mustReq(t, "https://api.example.com/a")
	}
	if err := SameOriginRedirectPolicy(mustReq(t, "https://api.example.com/b"), via); err == nil {
		t.Fatal("expected redirect limit error")
	}
}

func TestWithSameOriginRedirects(t *testing.T) {
	from := []*http.Request{mustReq(t, "https://api.example.com/a")}
	same := mustReq(t, "https://api.example.com/b")
	cross := mustReq(t, "https://evil.example.net/b")

	t.Run("nil next uses same-origin policy", func(t *testing.T) {
		policy := WithSameOriginRedirects(nil)
		if err := policy(cross, from); !errors.Is(err, ErrCrossOriginRedirect) {
			t.Fatalf("err = %v, want ErrCrossOriginRedirect", err)
		}
	})

	t.Run("existing policy still runs for same-origin hops", func(t *testing.T) {
		nextErr := errors.New("next policy refused")
		var calls int
		policy := WithSameOriginRedirects(func(*http.Request, []*http.Request) error {
			calls++
			return nextErr
		})
		if err := policy(same, from); !errors.Is(err, nextErr) {
			t.Fatalf("err = %v, want next policy error", err)
		}
		if err := policy(cross, from); !errors.Is(err, ErrCrossOriginRedirect) {
			t.Fatalf("err = %v, want ErrCrossOriginRedirect", err)
		}
		if calls != 1 {
			t.Errorf("next policy calls = %d, want 1 (not called for cross-origin)", calls)
		}
	})
}

// redirectPair starts a target server that records whether it was hit and the
// credentials it saw, and an upstream that redirects every request to the
// target. When sameOrigin is true the upstream redirects to itself instead.
type redirectPair struct {
	upstream   *httptest.Server
	target     *httptest.Server
	targetHits atomic.Int32
	gotAuth    atomic.Value
}

func newRedirectPair(t *testing.T, sameOrigin bool) *redirectPair {
	t.Helper()
	p := &redirectPair{}
	p.target = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.targetHits.Add(1)
		p.gotAuth.Store(r.Header.Get("Authorization"))
		_, _ = w.Write([]byte("target"))
	}))
	t.Cleanup(p.target.Close)

	p.upstream = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/final" {
			p.gotAuth.Store(r.Header.Get("Authorization"))
			_, _ = w.Write([]byte("final"))
			return
		}
		dest := p.target.URL + "/steal"
		if sameOrigin {
			dest = "/final"
		}
		http.Redirect(w, r, dest, http.StatusFound)
	}))
	t.Cleanup(p.upstream.Close)
	return p
}

func bearerSpec() ClientSpec {
	return ClientSpec{
		TransportMiddleware: func(base http.RoundTripper) http.RoundTripper {
			return &BearerTransport{Token: "s3cret", Base: base}
		},
	}
}

func TestRegistry_CredentialedClientRefusesCrossOriginRedirect(t *testing.T) {
	registries := map[string]*Registry{
		"plain":        NewRegistry(nil),
		"instrumented": NewRegistry(nil, WithObserver(NoOpHTTPClientObserver{})),
	}
	for name, r := range registries {
		t.Run(name, func(t *testing.T) {
			p := newRedirectPair(t, false)
			client, err := r.Build(bearerSpec())
			if err != nil {
				t.Fatalf("Build: %v", err)
			}

			resp, err := client.Get(p.upstream.URL + "/start")
			if err == nil {
				_ = resp.Body.Close()
				t.Fatal("expected cross-origin redirect to be refused")
			}
			if !errors.Is(err, ErrCrossOriginRedirect) {
				t.Errorf("err = %v, want ErrCrossOriginRedirect", err)
			}
			if hits := p.targetHits.Load(); hits != 0 {
				t.Errorf("target received %d requests, want 0", hits)
			}
		})
	}
}

func TestRegistry_CredentialedClientFollowsSameOriginRedirect(t *testing.T) {
	p := newRedirectPair(t, true)
	client, err := NewRegistry(nil).Build(bearerSpec())
	if err != nil {
		t.Fatalf("Build: %v", err)
	}

	resp, err := client.Get(p.upstream.URL + "/start")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
	if got, _ := p.gotAuth.Load().(string); got != "Bearer s3cret" {
		t.Errorf("Authorization at same-origin target = %q, want bearer token", got)
	}
}

func TestRegistry_UnauthenticatedClientKeepsDefaultRedirects(t *testing.T) {
	p := newRedirectPair(t, false)
	client, err := NewRegistry(nil).Build(ClientSpec{})
	if err != nil {
		t.Fatalf("Build: %v", err)
	}
	if client.CheckRedirect != nil {
		t.Error("unauthenticated client should keep the default redirect policy")
	}

	resp, err := client.Get(p.upstream.URL + "/start")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	_ = resp.Body.Close()
	if hits := p.targetHits.Load(); hits != 1 {
		t.Errorf("target received %d requests, want 1", hits)
	}
}

func TestRegistry_HeadersAuthClientGetsRedirectPolicy(t *testing.T) {
	r := NewRegistry(nil)
	client, err := r.Register("bop", ClientSpec{
		TransportMiddleware: func(base http.RoundTripper) http.RoundTripper {
			return &HeadersTransport{Headers: map[string]string{"x-rh-apitoken": "s3cret"}, Base: base}
		},
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if client.CheckRedirect == nil {
		t.Fatal("headers-auth client should have a same-origin redirect policy")
	}
}
