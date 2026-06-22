package server

import (
	"context"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"

	"github.com/project-kessel/parsec/internal/issuer"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

const bufconnSize = 1 << 20 // 1 MiB

// testEnv bundles a running server, gRPC connection, health client, and HTTP
// client. All communication uses in-memory transports (bufconn); no TCP ports
// or loopback addresses are involved.
type testEnv struct {
	Ctx          context.Context
	Srv          *Server
	GRPCConn     *grpc.ClientConn
	HealthClient healthpb.HealthClient
	HTTPClient   *http.Client
	HTTPBaseURL  string
}

// startTestServer creates in-memory listeners (bufconn), starts a server,
// dials a gRPC client via the same bufconn, and returns an HTTP client wired
// through a second bufconn. No real network I/O occurs.
func startTestServer(t *testing.T, cfg Config) *testEnv {
	t.Helper()

	grpcBuf := bufconn.Listen(bufconnSize)
	t.Cleanup(func() { _ = grpcBuf.Close() })

	httpBuf := bufconn.Listen(bufconnSize)
	t.Cleanup(func() { _ = httpBuf.Close() })

	cfg.GRPCListener = grpcBuf
	cfg.HTTPListener = httpBuf
	cfg.GRPCDialOptions = []grpc.DialOption{
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return grpcBuf.DialContext(ctx)
		}),
	}

	ctx, cancel := context.WithCancel(context.Background())

	srv := New(cfg)
	if err := srv.Start(ctx); err != nil {
		cancel()
		t.Fatalf("failed to start server: %v", err)
	}

	grpcConn, err := grpc.NewClient(
		"passthrough:///bufnet",
		grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) {
			return grpcBuf.DialContext(ctx)
		}),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		cancel()
		t.Fatalf("failed to dial gRPC: %v", err)
	}

	httpClient := &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return httpBuf.DialContext(ctx)
			},
		},
	}

	t.Cleanup(func() {
		_ = grpcConn.Close()
		_ = srv.Stop(ctx)
		cancel()
	})

	return &testEnv{
		Ctx:          ctx,
		Srv:          srv,
		GRPCConn:     grpcConn,
		HealthClient: healthpb.NewHealthClient(grpcConn),
		HTTPClient:   httpClient,
		HTTPBaseURL:  "http://bufnet",
	}
}

// setupStubDependencies creates stub implementations for testing server
// endpoints. Returns a trust store, token service, and issuer registry.
func setupStubDependencies() (trust.Store, *service.TokenService, service.Registry) {
	trustStore := trust.NewStubStore()

	stubValidator := trust.NewStubValidator(trust.CredentialTypeBearer)
	trustStore.AddValidator(stubValidator)

	dataSourceRegistry := service.NewDataSourceRegistry()

	issuerRegistry := service.NewSimpleRegistry()
	txnMappers := []service.ClaimMapper{service.NewPassthroughSubjectMapper()}
	reqMappers := []service.ClaimMapper{service.NewRequestAttributesMapper()}
	txnTokenIssuer := issuer.NewStubIssuer(issuer.StubIssuerConfig{
		IssuerURL:                 "https://parsec.test",
		TTL:                       5 * time.Minute,
		TransactionContextMappers: txnMappers,
		RequestContextMappers:     reqMappers,
	})
	issuerRegistry.Register(service.TokenTypeTransactionToken, txnTokenIssuer)

	trustDomain := "parsec.test"
	tokenService := service.NewTokenService(trustDomain, dataSourceRegistry, issuerRegistry, nil)

	return trustStore, tokenService, issuerRegistry
}

// stubServerConfig builds a Config with stub dependencies suitable for most
// server tests. Callers can override individual fields before passing to
// startTestServer.
func stubServerConfig() Config {
	trustStore, tokenService, issuerRegistry := setupStubDependencies()
	claimsFilterRegistry := NewStubClaimsFilterRegistry()
	return Config{
		AuthzServer:    NewAuthzServer(trustStore, tokenService, nil, DefaultCredentialSources(), nil),
		ExchangeServer: NewExchangeServer(trustStore, tokenService, claimsFilterRegistry, DefaultCredentialSources(), nil),
		JWKSServer:     NewJWKSServer(JWKSServerConfig{IssuerRegistry: issuerRegistry, Observer: NoOpServerObserver{}}),
		Observer:       NoOpServerObserver{},
	}
}

// httpGetJSON performs a GET request and returns the parsed JSON body.
// It asserts status 200.
func httpGetJSON(t *testing.T, client *http.Client, url string) map[string]string {
	t.Helper()

	resp, err := client.Get(url)
	if err != nil {
		t.Fatalf("GET %s failed: %v", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		t.Fatalf("GET %s: expected 200, got %d. Body: %s", url, resp.StatusCode, body)
	}

	return decodeJSONBody(t, resp.Body)
}

// decodeJSONBody reads an io.Reader and decodes the JSON body into a map.
func decodeJSONBody(t *testing.T, r io.Reader) map[string]string {
	t.Helper()

	var body map[string]string
	if err := json.NewDecoder(r).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON body: %v", err)
	}
	return body
}
