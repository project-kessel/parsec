package server

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/peer"
)

// TLSPeerInfo holds mTLS client certificate information extracted from the
// transport layer.
type TLSPeerInfo struct {
	Certificates []*x509.Certificate
}

// CredentialContext holds the normalized context needed by CredentialSource
// implementations to extract credentials. Callers build a CredentialContext
// from their specific transport (Envoy CheckRequest, gRPC context, etc.)
// before credential extraction.
type CredentialContext struct {
	Headers map[string]string // normalized lowercase header keys
	Cookies []*http.Cookie    // parsed from the cookie header; nil when absent
	TLSPeer *TLSPeerInfo      // mTLS client cert info; nil when absent
}

// CredentialContextFromCheckRequest builds a CredentialContext from an Envoy
// ext_authz CheckRequest's HTTP attributes.
func CredentialContextFromCheckRequest(req *authv3.CheckRequest) (CredentialContext, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	if httpReq == nil {
		return CredentialContext{}, fmt.Errorf("no HTTP request attributes")
	}
	headers := normalizeHeaderKeys(httpReq.GetHeaders())
	cookies, err := parseCookies(headers["cookie"])
	if err != nil {
		return CredentialContext{}, err
	}
	return CredentialContext{
		Headers: headers,
		Cookies: cookies,
	}, nil
}

// CredentialContextFromGRPC builds a CredentialContext from a gRPC server
// context, extracting metadata headers and TLS peer certificate info.
func CredentialContextFromGRPC(ctx context.Context) (CredentialContext, error) {
	tc := CredentialContext{}

	if md, ok := metadata.FromIncomingContext(ctx); ok {
		tc.Headers = make(map[string]string, len(md))
		for k, vals := range md {
			if len(vals) > 0 {
				tc.Headers[strings.ToLower(k)] = vals[0]
			}
		}
		cookies, err := parseCookies(tc.Headers["cookie"])
		if err != nil {
			return CredentialContext{}, err
		}
		tc.Cookies = cookies
	}

	if p, ok := peer.FromContext(ctx); ok {
		if tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo); ok {
			if len(tlsInfo.State.PeerCertificates) > 0 {
				tc.TLSPeer = &TLSPeerInfo{
					Certificates: tlsInfo.State.PeerCertificates,
				}
			}
		}
	}

	return tc, nil
}

func parseCookies(cookieHeader string) ([]*http.Cookie, error) {
	if cookieHeader == "" {
		return nil, nil
	}
	cookies, err := http.ParseCookie(cookieHeader)
	if err != nil {
		return nil, fmt.Errorf("malformed cookie header: %w", err)
	}
	return cookies, nil
}

func normalizeHeaderKeys(headers map[string]string) map[string]string {
	if len(headers) == 0 {
		return headers
	}
	out := make(map[string]string, len(headers))
	for k, v := range headers {
		out[strings.ToLower(k)] = v
	}
	return out
}
