package server

import (
	"context"
	"strings"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/google/uuid"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"

	parsecv1 "github.com/project-kessel/parsec/api/gen/parsec/v1"
	"github.com/project-kessel/parsec/internal/request"
)

const requestIDHeader = "x-request-id"

// requestIDInterceptor supplies local correlation for authorization and token
// exchange. It never changes the RPC payload, metadata, or response headers.
func requestIDInterceptor(ctx context.Context, req any, _ *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	var id string
	switch req := req.(type) {
	case *authv3.CheckRequest:
		id = request.ValidRequestID(request.HeaderValue(req.GetAttributes().GetRequest().GetHttp().GetHeaders(), requestIDHeader))
	case *parsecv1.ExchangeRequest:
	default:
		return handler(ctx, req)
	}
	if id == "" {
		if md, ok := metadata.FromIncomingContext(ctx); ok {
			values := md.Get(requestIDHeader)
			if len(values) == 1 {
				id = request.ValidRequestID(values[0])
			}
		}
	}
	if id == "" {
		id = uuid.NewString()
	}
	return handler(request.WithID(ctx, id), req)
}

// Match only the standard correlation header in addition to gateway defaults.
// This forwards it inside Parsec from the HTTP gateway to the local gRPC
// handler; it is not added to responses or outgoing dependency requests.
func incomingHeaderMatcher(name string) (string, bool) {
	if strings.EqualFold(name, requestIDHeader) {
		return requestIDHeader, true
	}
	return runtime.DefaultHeaderMatcher(name)
}
