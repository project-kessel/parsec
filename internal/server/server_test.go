package server

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/test/bufconn"
)

func TestStartRejectsNilGRPCListener(t *testing.T) {
	srv := New(stubServerConfig())
	err := srv.Start(context.Background())
	if err == nil {
		t.Fatal("expected error when gRPC listener is nil")
	}
	if !strings.Contains(err.Error(), "missing gRPC listener") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStartRejectsNilHTTPListener(t *testing.T) {
	cfg := stubServerConfig()
	cfg.GRPCListener = bufconn.Listen(bufconnSize)
	defer func() { _ = cfg.GRPCListener.Close() }()

	srv := New(cfg)
	err := srv.Start(context.Background())
	if err == nil {
		t.Fatal("expected error when HTTP listener is nil")
	}
	if !strings.Contains(err.Error(), "missing HTTP listener") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestStopForceClosesWhenContextCancelled(t *testing.T) {
	env := startTestServer(t, stubServerConfig())
	env.Srv.SetReady()

	watchCtx, watchCancel := context.WithCancel(context.Background())
	defer watchCancel()

	stream, err := env.HealthClient.Watch(watchCtx, &healthpb.HealthCheckRequest{Service: "readiness"})
	if err != nil {
		t.Fatalf("Watch(readiness) failed: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("Recv() failed: %v", err)
	}

	stopCtx, stopCancel := context.WithCancel(context.Background())
	stopCancel()

	done := make(chan error, 1)
	go func() {
		done <- env.Srv.Stop(stopCtx)
	}()

	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Stop() = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop blocked with an open RPC after the context was cancelled")
	}
}

// TestStopShutsDownHTTPBeforeGRPCDrain verifies that HTTP is closed while a
// long-lived gRPC stream still holds GracefulStop, so keep-alive HTTP clients
// are not left talking to a draining gateway for the whole gRPC drain.
func TestStopShutsDownHTTPBeforeGRPCDrain(t *testing.T) {
	env := startTestServer(t, stubServerConfig())
	env.Srv.SetReady()

	watchCtx, watchCancel := context.WithCancel(context.Background())
	defer watchCancel()

	stream, err := env.HealthClient.Watch(watchCtx, &healthpb.HealthCheckRequest{Service: "readiness"})
	if err != nil {
		t.Fatalf("Watch(readiness) failed: %v", err)
	}
	if _, err := stream.Recv(); err != nil {
		t.Fatalf("Recv() failed: %v", err)
	}

	liveReq, err := http.NewRequestWithContext(env.Ctx, http.MethodGet, env.HTTPBaseURL+"/healthz/live", nil)
	if err != nil {
		t.Fatalf("NewRequest: %v", err)
	}
	if resp, err := env.HTTPClient.Do(liveReq); err != nil {
		t.Fatalf("pre-stop /healthz/live: %v", err)
	} else {
		_ = resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			t.Fatalf("pre-stop /healthz/live status=%d", resp.StatusCode)
		}
	}

	stopCtx, stopCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer stopCancel()

	done := make(chan error, 1)
	go func() {
		done <- env.Srv.Stop(stopCtx)
	}()

	deadline := time.Now().Add(2 * time.Second)
	for {
		req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, env.HTTPBaseURL+"/healthz/live", nil)
		if err != nil {
			t.Fatalf("NewRequest: %v", err)
		}
		resp, err := env.HTTPClient.Do(req)
		if err != nil {
			break
		}
		_ = resp.Body.Close()
		if time.Now().After(deadline) {
			watchCancel()
			t.Fatal("HTTP still accepting after Stop started with an open gRPC stream")
		}
		time.Sleep(10 * time.Millisecond)
	}

	watchCancel()

	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Stop() = %v, want nil after watch cancelled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Stop did not return after watch cancelled")
	}
}

func TestGrpcDialEndpoint(t *testing.T) {
	tests := []struct {
		name string
		addr string
		want string
	}{
		{"ipv4 wildcard", "0.0.0.0:8080", "passthrough:///127.0.0.1:8080"},
		{"ipv6 wildcard", "[::]:8080", "passthrough:///[::1]:8080"},
		{"empty host", ":8080", "passthrough:///127.0.0.1:8080"},
		{"ipv4 loopback", "127.0.0.1:8080", "passthrough:///127.0.0.1:8080"},
		{"ipv6 loopback", "[::1]:8080", "passthrough:///[::1]:8080"},
		{"ipv4 specific", "192.168.1.1:9090", "passthrough:///192.168.1.1:9090"},
		{"opaque (bufconn)", "bufconn", "passthrough:///bufconn"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := grpcDialEndpoint(tt.addr)
			if got != tt.want {
				t.Errorf("grpcDialEndpoint(%q) = %q, want %q", tt.addr, got, tt.want)
			}
		})
	}
}
