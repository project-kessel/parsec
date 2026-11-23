package httpclient

import (
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// maxRedirects matches the net/http default redirect limit.
const maxRedirects = 10

// ErrCrossOriginRedirect is returned (wrapped in a *url.Error by
// [http.Client.Do]) when a credentialed client is redirected to a different
// origin.
var ErrCrossOriginRedirect = errors.New("redirect to a different origin refused for credentialed client")

// SameOriginRedirectPolicy is an [http.Client.CheckRedirect] function that only
// follows redirects that keep the scheme, host, and port of the original
// request. It also keeps the net/http limit of 10 redirects.
//
// Clients that add credentials in their transport (see [BearerTransport] and
// [HeadersTransport]) add them again on every redirect hop, and net/http never
// strips custom headers. Without this policy, an upstream that redirects to
// another origin, or downgrades https to http, would receive those credentials.
func SameOriginRedirectPolicy(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("stopped after %d redirects", maxRedirects)
	}
	if len(via) == 0 {
		return nil
	}
	from, to := via[0].URL, req.URL
	if !sameOrigin(from, to) {
		// Report origins only; paths and queries may carry sensitive values.
		return fmt.Errorf("%w: %s -> %s", ErrCrossOriginRedirect, origin(from), origin(to))
	}
	return nil
}

// WithSameOriginRedirects returns a redirect policy that applies
// [SameOriginRedirectPolicy] first and then next, if next is non-nil. Use it to
// add the same-origin rule without discarding an existing CheckRedirect.
func WithSameOriginRedirects(next func(*http.Request, []*http.Request) error) func(*http.Request, []*http.Request) error {
	if next == nil {
		return SameOriginRedirectPolicy
	}
	return func(req *http.Request, via []*http.Request) error {
		if err := SameOriginRedirectPolicy(req, via); err != nil {
			return err
		}
		return next(req, via)
	}
}

func sameOrigin(a, b *url.URL) bool {
	return strings.EqualFold(a.Scheme, b.Scheme) &&
		strings.EqualFold(a.Hostname(), b.Hostname()) &&
		effectivePort(a) == effectivePort(b)
}

func effectivePort(u *url.URL) string {
	if p := u.Port(); p != "" {
		return p
	}
	switch strings.ToLower(u.Scheme) {
	case "http":
		return "80"
	case "https":
		return "443"
	default:
		return ""
	}
}

func origin(u *url.URL) string {
	return strings.ToLower(u.Scheme) + "://" + u.Host
}
