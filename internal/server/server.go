package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"

	authv3 "github.com/envoyproxy/go-control-plane/envoy/service/auth/v3"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/health"
	healthpb "google.golang.org/grpc/health/grpc_health_v1"
	"google.golang.org/grpc/reflection"

	parsecv1 "github.com/project-kessel/parsec/api/gen/parsec/v1"
)

// healthReadinessService is the aggregate readiness key for Kubernetes gRPC
// readiness probes. It transitions to SERVING only when all application
// services are ready, and back to NOT_SERVING when any become unready.
// See: https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#define-a-grpc-liveness-probe
const healthReadinessService = "readiness"

// healthServices lists the full proto service names registered on the gRPC server.
// Per the gRPC Health Checking Protocol, each service is registered individually
// in the health server so clients can query per-service health status.
var healthServices = []string{
	"envoy.service.auth.v3.Authorization",
	"parsec.v1.TokenExchangeService",
	"parsec.v1.JWKSService",
}

// MuxConfigurer registers HTTP handlers on the server's mux during startup.
// Use this to add endpoints like /metrics or /debug/pprof without coupling
// the server to specific subsystem types.
type MuxConfigurer func(*http.ServeMux)

// Server manages the gRPC and HTTP servers
type Server struct {
	grpcServer   *grpc.Server
	httpServer   *http.Server
	healthServer *health.Server

	grpcListener    net.Listener
	httpListener    net.Listener
	grpcDialOptions []grpc.DialOption
	observer        LifecycleObserver
	muxConfigurer   MuxConfigurer

	authzServer    *AuthzServer
	exchangeServer *ExchangeServer
	jwksServer     *JWKSServer
	activeRequests atomic.Int64
}

// Config contains server configuration. Callers must supply pre-created
// listeners; the server itself has no concept of port numbers.
type Config struct {
	GRPCListener net.Listener
	HTTPListener net.Listener

	// GRPCDialOptions are extra dial options appended when the grpc-gateway
	// dials the gRPC server. Use this to supply a custom dialer for
	// in-memory transports (e.g. bufconn).
	GRPCDialOptions []grpc.DialOption

	AuthzServer    *AuthzServer
	ExchangeServer *ExchangeServer
	JWKSServer     *JWKSServer

	// Observer for server lifecycle events. Defaults to NoOpServerObserver{} if nil.
	Observer LifecycleObserver

	// MuxConfigurer, when non-nil, is applied to the HTTP mux during Start
	// to register additional handlers (e.g. /metrics for Prometheus scraping).
	MuxConfigurer MuxConfigurer
}

// New creates a new server with the given configuration.
func New(cfg Config) *Server {
	obs := cfg.Observer
	if obs == nil {
		obs = NoOpServerObserver{}
	}
	muxCfg := cfg.MuxConfigurer
	if muxCfg == nil {
		muxCfg = func(*http.ServeMux) {}
	}
	return &Server{
		grpcListener:    cfg.GRPCListener,
		httpListener:    cfg.HTTPListener,
		grpcDialOptions: cfg.GRPCDialOptions,
		observer:        obs,
		muxConfigurer:   muxCfg,
		authzServer:     cfg.AuthzServer,
		exchangeServer:  cfg.ExchangeServer,
		jwksServer:      cfg.JWKSServer,
	}
}

// Start starts both the gRPC and HTTP servers
func (s *Server) Start(ctx context.Context) error {
	if s.grpcListener == nil {
		return fmt.Errorf("missing gRPC listener")
	}
	if s.httpListener == nil {
		return fmt.Errorf("missing HTTP listener")
	}

	// Create gRPC server
	s.grpcServer = grpc.NewServer(grpc.UnaryInterceptor(s.trackSecurityRequest))

	// Register services
	authv3.RegisterAuthorizationServer(s.grpcServer, s.authzServer)
	parsecv1.RegisterTokenExchangeServiceServer(s.grpcServer, s.exchangeServer)
	parsecv1.RegisterJWKSServiceServer(s.grpcServer, s.jwksServer)

	// Register standard gRPC health checking service (grpc.health.v1.Health).
	// See: https://github.com/grpc/grpc/blob/master/doc/health-checking.md
	s.healthServer = health.NewServer()
	healthpb.RegisterHealthServer(s.grpcServer, s.healthServer)

	// Per the spec, register all services manually including the empty string
	// for overall server health (liveness). The empty string is set to SERVING
	// immediately and remains so until Shutdown() is called during Stop(),
	// which sets every service to NOT_SERVING. Per-service and readiness
	// statuses start as NOT_SERVING until SetReady() is called.
	s.healthServer.SetServingStatus("", healthpb.HealthCheckResponse_SERVING)
	s.healthServer.SetServingStatus(healthReadinessService, healthpb.HealthCheckResponse_NOT_SERVING)
	for _, svc := range healthServices {
		s.healthServer.SetServingStatus(svc, healthpb.HealthCheckResponse_NOT_SERVING)
	}

	// Register reflection service for grpcurl and other tools
	reflection.Register(s.grpcServer)

	// Create HTTP server with grpc-gateway.
	// Use passthrough resolver so the address is used as-is (works for both
	// TCP addresses and in-memory transports like bufconn).
	gwMux := runtime.NewServeMux(
		runtime.WithMarshalerOption("application/x-www-form-urlencoded", NewFormMarshaler()),
		runtime.WithErrorHandler(oauthHTTPErrorHandler),
		runtime.WithIncomingHeaderMatcher(auditIncomingHeaderMatcher),
		runtime.WithOutgoingHeaderMatcher(auditOutgoingHeaderMatcher),
	)
	opts := append(
		[]grpc.DialOption{grpc.WithTransportCredentials(insecure.NewCredentials())},
		s.grpcDialOptions...,
	)

	endpoint := grpcDialEndpoint(s.grpcListener.Addr().String())
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
	s.muxConfigurer(httpMux)
	httpMux.Handle("/", gwMux)

	s.httpServer = &http.Server{Handler: httpMux}

	// All fallible setup is complete. Launch the serve goroutines last so
	// that an early-return error never orphans a running goroutine.
	go func() {
		if err := s.grpcServer.Serve(s.grpcListener); err != nil && !errors.Is(err, grpc.ErrServerStopped) {
			s.observer.GRPCServeFailed(err)
		}
	}()
	go func() {
		if err := s.httpServer.Serve(s.httpListener); err != nil && err != http.ErrServerClosed {
			s.observer.HTTPServeFailed(err)
		}
	}()

	return nil
}

// SetReady transitions all per-service and the aggregate readiness
// health statuses to SERVING. Call this after all components have been
// successfully initialized.
func (s *Server) SetReady() {
	for _, svc := range healthServices {
		s.healthServer.SetServingStatus(svc, healthpb.HealthCheckResponse_SERVING)
	}
	s.healthServer.SetServingStatus(healthReadinessService, healthpb.HealthCheckResponse_SERVING)
}

// SetNotReady transitions all per-service and the aggregate readiness
// health statuses to NOT_SERVING.
func (s *Server) SetNotReady() {
	for _, svc := range healthServices {
		s.healthServer.SetServingStatus(svc, healthpb.HealthCheckResponse_NOT_SERVING)
	}
	s.healthServer.SetServingStatus(healthReadinessService, healthpb.HealthCheckResponse_NOT_SERVING)
}

// Stop gracefully stops both servers
func (s *Server) Stop(ctx context.Context) error {
	ctx, p := s.observer.StopStarted(ctx)
	defer p.End()

	// Signal health watchers that all services are going away.
	// Shutdown sets every registered service to NOT_SERVING and
	// ignores any future SetServingStatus calls.
	if s.healthServer != nil {
		s.healthServer.Shutdown()
	}

	if s.grpcServer != nil {
		stopped := make(chan struct{})
		go func() {
			s.grpcServer.GracefulStop()
			close(stopped)
		}()
		select {
		case <-stopped:
		case <-ctx.Done():
			interrupted := s.activeRequests.Load()
			s.grpcServer.Stop()
			if s.httpServer != nil {
				_ = s.httpServer.Close()
			}
			p.ShutdownFailed(interrupted)
			return ctx.Err()
		}
	}

	if s.httpServer != nil {
		if err := s.httpServer.Shutdown(ctx); err != nil {
			p.ShutdownFailed(s.activeRequests.Load())
			return err
		}
	}

	p.ShutdownCompleted(s.activeRequests.Load())
	return nil
}

func (s *Server) trackSecurityRequest(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (any, error) {
	switch info.FullMethod {
	case "/envoy.service.auth.v3.Authorization/Check", "/parsec.v1.TokenExchangeService/Exchange":
		s.activeRequests.Add(1)
		defer s.activeRequests.Add(-1)
	}
	return handler(ctx, req)
}

// grpcDialEndpoint builds a passthrough:/// endpoint suitable for grpc-gateway
// to dial. If the listener is bound to a wildcard address (0.0.0.0, [::], or
// empty host), it is replaced with the corresponding loopback address so the
// connection targets a dialable address. Non-TCP transports (e.g. bufconn)
// whose addresses aren't in host:port form are used as-is.
func grpcDialEndpoint(listenAddr string) string {
	host, port, err := net.SplitHostPort(listenAddr)
	if err != nil {
		return "passthrough:///" + listenAddr
	}
	switch host {
	case "", "0.0.0.0":
		host = "127.0.0.1"
	case "::":
		host = "::1"
	}
	return "passthrough:///" + net.JoinHostPort(host, port)
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
