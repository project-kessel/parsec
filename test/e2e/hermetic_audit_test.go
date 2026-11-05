package e2e_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/google/uuid"
	"github.com/rs/zerolog"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"

	parsecv1 "github.com/project-kessel/parsec/api/gen/parsec/v1"
	"github.com/project-kessel/parsec/internal/clock"
	"github.com/project-kessel/parsec/internal/issuer"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/observer"
	auditprobe "github.com/project-kessel/parsec/internal/probe/audit"
	"github.com/project-kessel/parsec/internal/server"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

// The running server uses in-memory listeners, including its HTTP → gRPC hop.
// This exercises production interceptor wiring without opening TCP ports.
type auditAPI struct {
	authz    authv3.AuthorizationClient
	exchange parsecv1.TokenExchangeServiceClient
	http     *http.Client
	output   *auditOutput
}

type auditOutput struct {
	mu     sync.Mutex
	buffer bytes.Buffer
}

func (o *auditOutput) Write(data []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.buffer.Write(data)
}

func (o *auditOutput) lastRequest(t *testing.T) map[string]any {
	t.Helper()
	records := o.records(t)
	for i := len(records) - 1; i >= 0; i-- {
		if records[i]["event"] == "parsec_request" {
			return records[i]
		}
	}
	t.Fatal("no terminal request audit record")
	return nil
}

func (o *auditOutput) records(t *testing.T) []map[string]any {
	t.Helper()
	o.mu.Lock()
	output := o.buffer.String()
	o.mu.Unlock()
	return auditRecords(t, output)
}

func newAuditAPI(t *testing.T, scripts []string) *auditAPI {
	t.Helper()
	output := &auditOutput{}
	// Exercise composite fan-out as used by deployed configurations.
	obs := observer.CompositeAll([]observer.Observer{
		observer.NoOp(), auditprobe.New(zerolog.New(output), auditprobe.Metadata{ServiceName: "parsec"}),
	})
	clk := clock.NewFixtureClock(time.Date(2024, 6, 15, 10, 0, 0, 0, time.UTC))
	registry := service.NewSimpleRegistry()
	var specs []server.TokenTypeSpec
	for i, tokenType := range []service.TokenType{service.TokenTypeTransactionToken, service.TokenTypeRHIdentity} {
		if i >= len(scripts) {
			break
		}
		m, err := mapper.NewCELMapper(scripts[i], mapper.WithClock(clk))
		require.NoError(t, err)
		registry.Register(tokenType, issuer.NewUnsignedIssuer(issuer.UnsignedIssuerConfig{
			TokenType: string(tokenType), ClaimMappers: []service.ClaimMapper{m}, Clock: clk,
		}))
		specs = append(specs, server.TokenTypeSpec{Type: tokenType, HeaderName: []string{"Transaction-Token", "x-rh-identity"}[i]})
	}
	tokens := service.NewTokenService("parsec.test", service.NewDataSourceRegistry(), registry, obs)
	store := trust.NewStubStore().AddValidator(trust.NewStubValidator(trust.CredentialTypeBearer, trust.CredentialTypeJWT).WithClock(clk))
	grpcListener, httpListener := bufconn.Listen(1<<20), bufconn.Listen(1<<20)
	dial := func(ctx context.Context, _ string) (net.Conn, error) { return grpcListener.DialContext(ctx) }
	ctx, cancel := context.WithCancel(context.Background())
	srv := server.New(server.Config{
		GRPCListener: grpcListener, HTTPListener: httpListener,
		GRPCDialOptions: []grpc.DialOption{grpc.WithContextDialer(dial)},
		AuthzServer:     server.NewAuthzServer(store, tokens, server.NewStaticAuthenticatedPolicy(specs), server.DefaultCredentialSources(), nil, nil, obs),
		ExchangeServer:  server.NewExchangeServer(store, tokens, server.NewStubClaimsFilterRegistry(), server.DefaultCredentialSources(), obs),
		JWKSServer:      server.NewJWKSServer(server.JWKSServerConfig{IssuerRegistry: registry, Observer: obs}), Observer: obs,
	})
	require.NoError(t, srv.Start(ctx))
	conn, err := grpc.NewClient("passthrough:///audit-test", grpc.WithContextDialer(dial), grpc.WithTransportCredentials(insecure.NewCredentials()))
	require.NoError(t, err)
	transport := &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return httpListener.DialContext(ctx) }}
	t.Cleanup(func() {
		transport.CloseIdleConnections()
		_ = conn.Close()
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer stopCancel()
		require.NoError(t, srv.Stop(stopCtx))
		cancel()
	})
	return &auditAPI{authv3.NewAuthorizationClient(conn), parsecv1.NewTokenExchangeServiceClient(conn), &http.Client{Transport: transport}, output}
}

func auditExchangeRequest() *parsecv1.ExchangeRequest {
	return &parsecv1.ExchangeRequest{
		GrantType:    "urn:ietf:params:oauth:grant-type:token-exchange",
		SubjectToken: "opaque-token", SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
	}
}

func TestHermeticAuditCorrelationStaysLocal(t *testing.T) {
	api := newAuditAPI(t, []string{`{"path": request.path, "headers": request.headers}`})
	var generatedIDs []string
	for _, id := range []string{"gateway-id", "", "invalid/id"} {
		req := checkRequestWithBearer("opaque-token")
		req.Attributes.Request.Http.Path = "/api/test?keep=query"
		if id != "" {
			req.Attributes.Request.Http.Headers["x-request-id"] = id
		}
		var headers, trailers metadata.MD
		resp, err := api.authz.Check(context.Background(), req, grpc.Header(&headers), grpc.Trailer(&trailers))
		require.NoError(t, err)
		require.Zero(t, resp.Status.Code)
		require.Empty(t, headers.Get("x-request-id"))
		require.Empty(t, trailers.Get("x-request-id"))
		upstream := resp.GetOkResponse().Headers
		require.Len(t, upstream, 1, "only the issued token is added upstream")
		require.Equal(t, "Transaction-Token", upstream[0].Header.Key)
		claimsJSON, err := base64.StdEncoding.DecodeString(upstream[0].Header.Value)
		require.NoError(t, err)
		var tokenClaims map[string]any
		require.NoError(t, json.Unmarshal(claimsJSON, &tokenClaims))
		require.Equal(t, "/api/test?keep=query", tokenClaims["path"])
		tokenHeaders := tokenClaims["headers"].(map[string]any)
		if id == "" {
			require.NotContains(t, tokenHeaders, "x-request-id")
		} else {
			require.Equal(t, id, tokenHeaders["x-request-id"])
		}
		observed := api.output.lastRequest(t)["request_id"].(string)
		if id == "gateway-id" {
			require.Equal(t, id, observed)
		} else {
			_, err := uuid.Parse(observed)
			require.NoError(t, err)
			generatedIDs = append(generatedIDs, observed)
		}
	}
	require.NotEqual(t, generatedIDs[0], generatedIDs[1])

	ctx := metadata.NewOutgoingContext(context.Background(), metadata.Pairs("x-request-id", "exchange-id"))
	var headers metadata.MD
	_, err := api.exchange.Exchange(ctx, auditExchangeRequest(), grpc.Header(&headers))
	require.NoError(t, err)
	require.Empty(t, headers.Get("x-request-id"))
	require.Equal(t, "exchange-id", api.output.lastRequest(t)["request_id"])

	// HTTP correlation must survive the internal gateway hop, without being
	// copied into the HTTP response or into the mapped request attributes.
	for _, id := range []string{"http-id", ""} {
		body := `{"grant_type":"urn:ietf:params:oauth:grant-type:token-exchange","subject_token":"opaque-token","subject_token_type":"urn:ietf:params:oauth:token-type:jwt"}`
		req, err := http.NewRequest(http.MethodPost, "http://parsec.test/v1/token", strings.NewReader(body))
		require.NoError(t, err)
		req.Header.Set("Content-Type", "application/json")
		if id != "" {
			req.Header.Set("x-request-id", id)
		}
		resp, err := api.http.Do(req)
		require.NoError(t, err)
		_, err = io.Copy(io.Discard, resp.Body)
		require.NoError(t, err)
		require.NoError(t, resp.Body.Close())
		require.Equal(t, http.StatusOK, resp.StatusCode)
		require.Empty(t, resp.Header.Get("x-request-id"))
		observed := api.output.lastRequest(t)["request_id"].(string)
		if id != "" {
			require.Equal(t, id, observed)
		} else {
			_, err := uuid.Parse(observed)
			require.NoError(t, err)
		}
	}
}

func TestHermeticAuditIssuanceOutcomes(t *testing.T) {
	txn, identity := string(service.TokenTypeTransactionToken), string(service.TokenTypeRHIdentity)
	tests := []struct {
		name            string
		scripts         []string
		outcome, reason string
		grpcCode        codes.Code
		httpStatus      int
		issued          []any
	}{
		{"success", []string{`{"ok": true}`}, "success", "", codes.OK, 0, []any{txn}},
		{"denial", []string{`accessDenied("denied")`}, "denied", "token_issuance_denied", codes.PermissionDenied, 403, nil},
		{"failure", []string{`fail("unavailable")`}, "failure", "token_issuance_failed", codes.Internal, 500, nil},
		{"missing issuer", nil, "failure", "token_issuance_failed", codes.Internal, 500, nil},
		{"partial denial", []string{`{"ok": true}`, `accessDenied("denied")`}, "denied", "token_issuance_denied", codes.PermissionDenied, 403, []any{txn}},
		{"partial failure", []string{`{"ok": true}`, `fail("unavailable")`}, "failure", "token_issuance_failed", codes.Internal, 500, []any{txn}},
		{"denial then failure", []string{`accessDenied("denied")`, `fail("unavailable")`}, "failure", "token_issuance_failed", codes.Internal, 500, nil},
		{"compliance denial then failure", []string{`accessDenied("denied", "compliance_denied")`, `fail("unavailable")`}, "failure", "token_issuance_failed", codes.Internal, 500, nil},
		{"first denial selects terminal reason", []string{`accessDenied("denied")`, `accessDenied("denied", "compliance_denied")`}, "denied", "token_issuance_denied", codes.PermissionDenied, 403, nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			api := newAuditAPI(t, tt.scripts)
			resp, err := api.authz.Check(context.Background(), checkRequestWithBearer("opaque-token"))
			require.NoError(t, err)
			require.Equal(t, int32(tt.grpcCode), resp.Status.Code)
			if tt.grpcCode != codes.OK {
				require.Equal(t, tt.httpStatus, int(resp.GetDeniedResponse().Status.Code))
			}
			record := api.output.lastRequest(t)
			require.Equal(t, tt.outcome, record["outcome"])
			if tt.reason != "" {
				require.Equal(t, tt.reason, record["reason_code"])
			} else {
				require.NotContains(t, record, "reason_code")
			}
			resource := record["resource"].(map[string]any)
			requested := []any{txn}
			if len(tt.scripts) == 2 {
				requested = append(requested, identity)
			}
			require.Equal(t, requested, resource["requested_token_types"])
			if tt.issued == nil {
				require.NotContains(t, resource, "token_types")
			} else {
				require.Equal(t, tt.issued, resource["token_types"])
			}
			if strings.Contains(strings.Join(tt.scripts, ""), "compliance_denied") {
				var count int
				for _, record := range api.output.records(t) {
					if record["event"] == "parsec_auth_compliance_failure" {
						count++
						require.Equal(t, "denied", record["outcome"])
						require.Equal(t, "compliance_denied", record["reason_code"])
					}
				}
				require.Equal(t, 1, count)
			}
		})
	}
}

func TestHermeticAuditExchangeDefaultTypeAndErrors(t *testing.T) {
	for _, script := range []string{`{"ok": true}`, `accessDenied("denied")`, `accessDenied("denied", "compliance_denied")`, `fail("unavailable")`} {
		t.Run(script, func(t *testing.T) {
			api := newAuditAPI(t, []string{script})
			resp, err := api.exchange.Exchange(context.Background(), auditExchangeRequest())
			record := api.output.lastRequest(t)
			resource := record["resource"].(map[string]any)
			types := []any{string(service.TokenTypeTransactionToken)}
			require.Equal(t, types, resource["requested_token_types"])
			switch script {
			case `{"ok": true}`:
				require.NoError(t, err)
				require.Equal(t, string(service.TokenTypeTransactionToken), resp.IssuedTokenType)
				require.Equal(t, types, resource["token_types"])
			case `accessDenied("denied")`, `accessDenied("denied", "compliance_denied")`:
				require.Equal(t, codes.PermissionDenied, status.Code(err))
				require.Equal(t, "denied", status.Convert(err).Message())
				require.Equal(t, "denied", record["outcome"])
				require.NotContains(t, resource, "token_types")
				details := status.Convert(err).Details()
				require.Len(t, details, 1)
				info := details[0].(*errdetails.ErrorInfo)
				require.Equal(t, "access_denied", info.Reason)
				require.Equal(t, map[string]string{"error_description": "denied"}, info.Metadata,
					"audit classification must not change the gRPC error details")
				if strings.Contains(script, "compliance_denied") {
					require.Equal(t, "compliance_denied", record["reason_code"])
				}
			default:
				require.Equal(t, codes.Internal, status.Code(err))
				require.Contains(t, status.Convert(err).Message(), "unavailable")
				require.Equal(t, "failure", record["outcome"])
				require.NotContains(t, resource, "token_types")
			}
		})
	}
}
