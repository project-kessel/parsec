package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	parsecv1 "github.com/project-kessel/parsec/api/gen/parsec/v1"
)

// healthServices lists the full proto service names registered on the gRPC server.
// Per the gRPC Health Checking Protocol, each service is registered individually
// in the health server so clients can query per-service health status.
var healthServices = []string{
	"envoy.service.auth.v3.Authorization",
	"parsec.v1.TokenExchangeService",
	"parsec.v1.JWKSService",
}

// Server manages the gRPC and HTTP servers
type Server struct {
	grpcServer   *grpc.Server
	httpServer   *http.Server
	healthServer *health.Server

	grpcPort int
	httpPort int

	authzServer    *AuthzServer
	exchangeServer *ExchangeServer
	jwksServer     *JWKSServer
}

// Config contains server configuration
type Config struct {
	GRPCPort int
	HTTPPort int

	AuthzServer    *AuthzServer
	ExchangeServer *ExchangeServer
	JWKSServer     *JWKSServer
}

// New creates a new server with the given configuration
func New(cfg Config) *Server {
	return &Server{
		grpcPort:       cfg.GRPCPort,
		httpPort:       cfg.HTTPPort,
		authzServer:    cfg.AuthzServer,
		exchangeServer: cfg.ExchangeServer,
		jwksServer:     cfg.JWKSServer,
	}
}

// Start starts both the gRPC and HTTP servers
func (s *Server) Start(ctx context.Context) error {
	// Create gRPC server
	s.grpcServer = grpc.NewServer()

	// Register services
	authv3.RegisterAuthorizationServer(s.grpcServer, s.authzServer)
	parsecv1.RegisterTokenExchangeServiceServer(s.grpcServer, s.exchangeServer)
	parsecv1.RegisterJWKSServiceServer(s.grpcServer, s.jwksServer)

	// Register standard gRPC health checking service (grpc.health.v1.Health).
	// See: https://github.com/grpc/grpc/blob/master/doc/health-checking.md
	// The empty string "" is set to SERVING by default (overall server health / liveness).
	s.healthServer = health.NewServer()
	healthpb.RegisterHealthServer(s.grpcServer, s.healthServer)

	// Register per-service health status — initially NOT_SERVING until SetReady() is called.
	for _, svc := range healthServices {
		s.healthServer.SetServingStatus(svc, healthpb.HealthCheckResponse_NOT_SERVING)
	}

	// Register reflection service for grpcurl and other tools
	reflection.Register(s.grpcServer)

	// Start gRPC server
	grpcListener, err := net.Listen("tcp", fmt.Sprintf(":%d", s.grpcPort))
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port %d: %w", s.grpcPort, err)
	}

	go func() {
		fmt.Printf("gRPC server listening on :%d\n", s.grpcPort)
		if err := s.grpcServer.Serve(grpcListener); err != nil {
			fmt.Printf("gRPC server error: %v\n", err)
		}
	}()

	// Create HTTP server with grpc-gateway
	// Register custom marshaler for application/x-www-form-urlencoded (RFC 8693 compliance)
	gwMux := runtime.NewServeMux(
		runtime.WithMarshalerOption("application/x-www-form-urlencoded", NewFormMarshaler()),
	)
	opts := []grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())}

	// Register HTTP handlers (transcoding from gRPC)
	endpoint := fmt.Sprintf("localhost:%d", s.grpcPort)
	if err := parsecv1.RegisterTokenExchangeServiceHandlerFromEndpoint(ctx, gwMux, endpoint, opts); err != nil {
		return fmt.Errorf("failed to register token exchange handler: %w", err)
	}
	if err := parsecv1.RegisterJWKSServiceHandlerFromEndpoint(ctx, gwMux, endpoint, opts); err != nil {
		return fmt.Errorf("failed to register JWKS handler: %w", err)
	}

	// Build top-level HTTP mux with health endpoints and grpc-gateway routes
	httpMux := http.NewServeMux()
	httpMux.HandleFunc("GET /healthz/live", s.handleLiveness)
	httpMux.HandleFunc("GET /healthz/ready", s.handleReadiness)
	httpMux.Handle("/", gwMux)

	// Start HTTP server
	s.httpServer = &http.Server{
		Addr:    fmt.Sprintf(":%d", s.httpPort),
		Handler: httpMux,
	}

	go func() {
		fmt.Printf("HTTP server (grpc-gateway) listening on :%d\n", s.httpPort)
		if err := s.httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("HTTP server error: %v\n", err)
		}
	}()

	return nil
}

// SetReady transitions all per-service health statuses to SERVING.
// Call this after all components have been successfully initialized.
func (s *Server) SetReady() {
	for _, svc := range healthServices {
		s.healthServer.SetServingStatus(svc, healthpb.HealthCheckResponse_SERVING)
	}
}

// SetNotReady transitions all per-service health statuses to NOT_SERVING.
func (s *Server) SetNotReady() {
	for _, svc := range healthServices {
		s.healthServer.SetServingStatus(svc, healthpb.HealthCheckResponse_NOT_SERVING)
	}
}

// Stop gracefully stops both servers
func (s *Server) Stop(ctx context.Context) error {
	// Signal health watchers that all services are going away.
	// Shutdown sets every registered service to NOT_SERVING and
	// ignores any future SetServingStatus calls.
	if s.healthServer != nil {
		s.healthServer.Shutdown()
	}

	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}

	if s.httpServer != nil {
		return s.httpServer.Shutdown(ctx)
	}

	return nil
}

// handleLiveness is the HTTP liveness probe handler.
// It always returns 200 OK if the process is running.
func (s *Server) handleLiveness(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "OK"})
}

// handleReadiness is the HTTP readiness probe handler.
// It queries the gRPC health server for every registered per-service status
// and returns 200 only when ALL services are SERVING, 503 otherwise.
func (s *Server) handleReadiness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")

	for _, svc := range healthServices {
		resp, err := s.healthServer.Check(r.Context(), &healthpb.HealthCheckRequest{
			Service: svc,
		})
		if err != nil || resp.Status != healthpb.HealthCheckResponse_SERVING {
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"status": "NOT_SERVING", "service": svc})
			return
		}
	}

	w.WriteHeader(http.StatusOK)
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "SERVING"})
}
