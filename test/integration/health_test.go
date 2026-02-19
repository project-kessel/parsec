package integration

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/status"

	"github.com/project-kessel/parsec/internal/server"
)

// healthServiceNames mirrors the per-service names registered by the server.
// Defined once here to keep the three phase subtests in sync.
var healthServiceNames = []string{
	"envoy.service.auth.v3.Authorization",
	"parsec.v1.TokenExchangeService",
	"parsec.v1.JWKSService",
}

// TestHealthEndpoints validates the full health check lifecycle through both
// HTTP and gRPC interfaces. The test mirrors how serve.go uses the server:
//
//	Start (NOT_SERVING) → SetReady (SERVING) → SetNotReady (NOT_SERVING) → Stop
//
// Subtests run sequentially and share one server, following the same pattern
// as TestJWKSEndpoint.
func TestHealthEndpoints(t *testing.T) {
	env := startHealthTestEnv(t, 19095, 18085)

	httpClient := &http.Client{Timeout: 5 * time.Second}

	// ================================================================
	// Phase 1: Before SetReady — services are NOT_SERVING
	// ================================================================

	t.Run("HTTP liveness returns 200 before SetReady", func(t *testing.T) {
		body := httpGet(t, httpClient, fmt.Sprintf("http://localhost:%d/healthz/live", env.HTTPPort))

		if body["status"] != "OK" {
			t.Errorf("expected status OK, got %q", body["status"])
		}
	})

	t.Run("HTTP readiness returns 503 before SetReady", func(t *testing.T) {
		resp, err := httpClient.Get(fmt.Sprintf("http://localhost:%d/healthz/ready", env.HTTPPort))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", resp.StatusCode)
		}

		body := decodeJSON(t, resp.Body)
		if body["status"] != "NOT_SERVING" {
			t.Errorf("expected status NOT_SERVING, got %q", body["status"])
		}
		// The response should identify which service failed
		if body["service"] == "" {
			t.Error("expected a service name in the response")
		}
	})

	t.Run("gRPC overall health returns SERVING (liveness)", func(t *testing.T) {
		// The empty string "" is the overall server health (set to SERVING by default).
		resp, err := env.HealthClient.Check(env.Ctx, &healthpb.HealthCheckRequest{Service: ""})
		if err != nil {
			t.Fatalf("Health/Check failed: %v", err)
		}
		if resp.Status != healthpb.HealthCheckResponse_SERVING {
			t.Errorf("expected SERVING for overall health, got %v", resp.Status)
		}
	})

	t.Run("gRPC per-service health returns NOT_SERVING before SetReady", func(t *testing.T) {
		for _, svc := range healthServiceNames {
			t.Run(svc, func(t *testing.T) {
				resp, err := env.HealthClient.Check(env.Ctx, &healthpb.HealthCheckRequest{Service: svc})
				if err != nil {
					t.Fatalf("Health/Check(%q) failed: %v", svc, err)
				}
				if resp.Status != healthpb.HealthCheckResponse_NOT_SERVING {
					t.Errorf("expected NOT_SERVING, got %v", resp.Status)
				}
			})
		}
	})

	// ================================================================
	// Phase 2: After SetReady — all services SERVING
	// ================================================================

	env.Srv.SetReady()

	t.Run("HTTP readiness returns 200 after SetReady", func(t *testing.T) {
		resp, err := httpClient.Get(fmt.Sprintf("http://localhost:%d/healthz/ready", env.HTTPPort))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("expected 200, got %d", resp.StatusCode)
		}

		body := decodeJSON(t, resp.Body)
		if body["status"] != "SERVING" {
			t.Errorf("expected status SERVING, got %q", body["status"])
		}
	})

	t.Run("gRPC per-service health returns SERVING after SetReady", func(t *testing.T) {
		for _, svc := range healthServiceNames {
			t.Run(svc, func(t *testing.T) {
				resp, err := env.HealthClient.Check(env.Ctx, &healthpb.HealthCheckRequest{Service: svc})
				if err != nil {
					t.Fatalf("Health/Check(%q) failed: %v", svc, err)
				}
				if resp.Status != healthpb.HealthCheckResponse_SERVING {
					t.Errorf("expected SERVING, got %v", resp.Status)
				}
			})
		}
	})

	// ================================================================
	// Phase 3: After SetNotReady — simulates degraded state
	// ================================================================

	env.Srv.SetNotReady()

	t.Run("HTTP readiness returns 503 after SetNotReady", func(t *testing.T) {
		resp, err := httpClient.Get(fmt.Sprintf("http://localhost:%d/healthz/ready", env.HTTPPort))
		if err != nil {
			t.Fatalf("request failed: %v", err)
		}
		defer func() { _ = resp.Body.Close() }()

		if resp.StatusCode != http.StatusServiceUnavailable {
			t.Fatalf("expected 503, got %d", resp.StatusCode)
		}

		body := decodeJSON(t, resp.Body)
		if body["status"] != "NOT_SERVING" {
			t.Errorf("expected status NOT_SERVING, got %q", body["status"])
		}
	})

	t.Run("gRPC per-service health returns NOT_SERVING after SetNotReady", func(t *testing.T) {
		for _, svc := range healthServiceNames {
			t.Run(svc, func(t *testing.T) {
				resp, err := env.HealthClient.Check(env.Ctx, &healthpb.HealthCheckRequest{Service: svc})
				if err != nil {
					t.Fatalf("Health/Check(%q) failed: %v", svc, err)
				}
				if resp.Status != healthpb.HealthCheckResponse_NOT_SERVING {
					t.Errorf("expected NOT_SERVING, got %v", resp.Status)
				}
			})
		}
	})
}

// TestHealthEndpoints_UnknownService verifies that querying an unregistered
// service returns gRPC NOT_FOUND, per the gRPC Health Checking Protocol spec.
func TestHealthEndpoints_UnknownService(t *testing.T) {
	env := startHealthTestEnv(t, 19096, 18086)

	t.Run("gRPC health check for unknown service returns NOT_FOUND", func(t *testing.T) {
		_, err := env.HealthClient.Check(env.Ctx, &healthpb.HealthCheckRequest{
			Service: "nonexistent.UnknownService",
		})
		if err == nil {
			t.Fatal("expected error for unknown service, got nil")
		}

		st, ok := status.FromError(err)
		if !ok {
			t.Fatalf("expected gRPC status error, got: %v", err)
		}
		if st.Code() != codes.NotFound {
			t.Errorf("expected NOT_FOUND, got %v", st.Code())
		}
	})
}

// TestHealthEndpoints_WatchStream verifies that the gRPC Watch RPC delivers
// real-time status updates when health transitions occur, as specified by
// https://github.com/grpc/grpc/blob/master/doc/health-checking.md
func TestHealthEndpoints_WatchStream(t *testing.T) {
	env := startHealthTestEnv(t, 19098, 18088)

	// Pick one service to watch (the protocol works the same for all).
	const watchedService = "parsec.v1.TokenExchangeService"

	watchCtx, watchCancel := context.WithTimeout(env.Ctx, 10*time.Second)
	defer watchCancel()

	stream, err := env.HealthClient.Watch(watchCtx, &healthpb.HealthCheckRequest{
		Service: watchedService,
	})
	if err != nil {
		t.Fatalf("Watch(%q) failed: %v", watchedService, err)
	}

	// The first message on the stream should reflect the current status.
	// Before SetReady, all per-service statuses are NOT_SERVING.
	t.Run("initial Watch message is NOT_SERVING", func(t *testing.T) {
		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv() failed: %v", err)
		}
		if resp.Status != healthpb.HealthCheckResponse_NOT_SERVING {
			t.Errorf("expected NOT_SERVING, got %v", resp.Status)
		}
	})

	// Transition to ready — the stream should deliver a SERVING update.
	env.Srv.SetReady()

	t.Run("Watch delivers SERVING after SetReady", func(t *testing.T) {
		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv() failed: %v", err)
		}
		if resp.Status != healthpb.HealthCheckResponse_SERVING {
			t.Errorf("expected SERVING, got %v", resp.Status)
		}
	})

	// Transition back to not-ready — the stream should deliver NOT_SERVING.
	env.Srv.SetNotReady()

	t.Run("Watch delivers NOT_SERVING after SetNotReady", func(t *testing.T) {
		resp, err := stream.Recv()
		if err != nil {
			t.Fatalf("Recv() failed: %v", err)
		}
		if resp.Status != healthpb.HealthCheckResponse_NOT_SERVING {
			t.Errorf("expected NOT_SERVING, got %v", resp.Status)
		}
	})
}

// --- test helpers ---

// healthTestEnv bundles a running server, gRPC health client, and HTTP port
// for health endpoint integration tests.
type healthTestEnv struct {
	Ctx          context.Context
	Srv          *server.Server
	HealthClient healthpb.HealthClient
	HTTPPort     int
}

// startHealthTestEnv creates dependencies, starts a server on the given ports,
// waits for it to be ready, dials a gRPC health client, and registers cleanup
// via t.Cleanup. Every health integration test uses this as its first line.
func startHealthTestEnv(t *testing.T, grpcPort, httpPort int) *healthTestEnv {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	trustStore, tokenService, issuerRegistry := setupTestDependencies()
	claimsFilterRegistry := server.NewStubClaimsFilterRegistry()

	srv := server.New(server.Config{
		GRPCPort:       grpcPort,
		HTTPPort:       httpPort,
		AuthzServer:    server.NewAuthzServer(trustStore, tokenService, nil, nil),
		ExchangeServer: server.NewExchangeServer(trustStore, tokenService, claimsFilterRegistry, nil),
		JWKSServer:     server.NewJWKSServer(server.JWKSServerConfig{IssuerRegistry: issuerRegistry, Logger: slog.Default()}),
	})

	if err := srv.Start(ctx); err != nil {
		cancel()
		t.Fatalf("Failed to start server on :%d/:%d: %v", grpcPort, httpPort, err)
	}

	waitForServer(t, httpPort, 5*time.Second)

	grpcConn, err := grpc.NewClient(
		fmt.Sprintf("localhost:%d", grpcPort),
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		cancel()
		t.Fatalf("Failed to dial gRPC on :%d: %v", grpcPort, err)
	}

	t.Cleanup(func() {
		_ = grpcConn.Close()
		_ = srv.Stop(ctx)
		cancel()
	})

	return &healthTestEnv{
		Ctx:          ctx,
		Srv:          srv,
		HealthClient: healthpb.NewHealthClient(grpcConn),
		HTTPPort:     httpPort,
	}
}

// httpGet performs a GET request and returns the parsed JSON body.
// It asserts status 200.
func httpGet(t *testing.T, client *http.Client, url string) map[string]string {
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

	return decodeJSON(t, resp.Body)
}

// decodeJSON reads an io.Reader and decodes the JSON body into a map.
func decodeJSON(t *testing.T, r io.Reader) map[string]string {
	t.Helper()

	var body map[string]string
	if err := json.NewDecoder(r).Decode(&body); err != nil {
		t.Fatalf("failed to decode JSON body: %v", err)
	}
	return body
}
