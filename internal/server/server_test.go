package server

import (
	"context"
	"errors"
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
