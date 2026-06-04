package server

import (
	"context"
	"crypto/x509"
	"fmt"
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

// TransportContext is a transport-neutral representation of request metadata
// used by CredentialSource implementations. Callers normalize their specific
// transport (Envoy CheckRequest, gRPC context, etc.) into this struct before
// credential extraction.
type TransportContext struct {
	Headers map[string]string // normalized lowercase header keys
	Path    string            // request path; empty for gRPC-native calls
	TLSPeer *TLSPeerInfo     // mTLS client cert info; nil when absent
}

// TransportContextFromCheckRequest builds a TransportContext from an Envoy
// ext_authz CheckRequest's HTTP attributes.
func TransportContextFromCheckRequest(req *authv3.CheckRequest) (TransportContext, error) {
	httpReq := req.GetAttributes().GetRequest().GetHttp()
	if httpReq == nil {
		return TransportContext{}, fmt.Errorf("no HTTP request attributes")
	}
	return TransportContext{
		Headers: normalizeHeaderKeys(httpReq.GetHeaders()),
		Path:    httpReq.GetPath(),
	}, nil
}

// TransportContextFromGRPC builds a TransportContext from a gRPC server
// context, extracting metadata headers and TLS peer certificate info.
func TransportContextFromGRPC(ctx context.Context) TransportContext {
	tc := TransportContext{}

	if md, ok := metadata.FromIncomingContext(ctx); ok {
		tc.Headers = make(map[string]string, len(md))
		for k, vals := range md {
			if len(vals) > 0 {
				tc.Headers[strings.ToLower(k)] = vals[0]
			}
		}
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

	return tc
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
