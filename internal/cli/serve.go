package cli

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/rs/zerolog"
	"github.com/spf13/cobra"

	"github.com/project-kessel/parsec/internal/config"
	"github.com/project-kessel/parsec/internal/server"
)

// NewServeCmd creates the serve command
func NewServeCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the parsec server",
		Long: `Start the parsec gRPC and HTTP servers.

The server will:
  - Listen for gRPC requests (ext_authz, token exchange)
  - Listen for HTTP requests (token exchange via gRPC-gateway transcoding)
  - Load configuration from file, environment variables, and command-line flags

Configuration precedence (highest to lowest):
  1. Command-line flags
  2. Environment variables (PARSEC_*)
  3. Configuration file (if --config or PARSEC_CONFIG is set)
  4. Built-in defaults

Examples:
  # Start with default settings
  parsec serve

  # Override server ports
  parsec serve --server-grpc-port 9091 --server-http-port 8081

  # Override trust domain
  parsec serve --trust-domain prod.example.com

  # Use custom config file
  parsec serve --config /etc/parsec/config.yaml

  # Combine multiple overrides
  parsec serve --config ./my-config.yaml --server-grpc-port 9091`,
		RunE: runServe,
	}

	// Auto-register all config flags
	config.RegisterFlags(cmd.Flags())

	return cmd
}

func runServe(cmd *cobra.Command, args []string) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	bootstrapLog := zerolog.New(os.Stdout).With().Timestamp().Logger()

	// 1. Determine config file path
	configPath := configFile
	if configPath == "" {
		configPath = os.Getenv("PARSEC_CONFIG")
	}

	// 2. Load configuration (file + env vars + flags)
	loader, err := config.NewLoaderWithFlags(configPath, cmd.Flags())
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	cfg, err := loader.Get()
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// 3. Create provider and build components
	provider := config.NewProvider(cfg)

	obs, err := provider.Observer()
	if err != nil {
		return fmt.Errorf("failed to create observer: %w", err)
	}

	trustStore, err := provider.TrustStore()
	if err != nil {
		return fmt.Errorf("failed to create trust store: %w", err)
	}

	tokenService, err := provider.TokenService()
	if err != nil {
		return fmt.Errorf("failed to create token service: %w", err)
	}

	authzCheckPolicy, err := provider.AuthzCheckPolicy()
	if err != nil {
		return fmt.Errorf("failed to get authz check policy: %w", err)
	}

	credentialSources, err := provider.CredentialSources()
	if err != nil {
		return fmt.Errorf("failed to get credential sources: %w", err)
	}

	claimsFilterRegistry, err := provider.ExchangeServerClaimsFilterRegistry()
	if err != nil {
		return fmt.Errorf("failed to create claims filter registry: %w", err)
	}

	issuerRegistry, err := provider.IssuerRegistry()
	if err != nil {
		return fmt.Errorf("failed to create issuer registry: %w", err)
	}

	// 4. Create service handlers
	authzServer := server.NewAuthzServer(trustStore, tokenService, authzCheckPolicy, credentialSources, obs)

	exchangeServer := server.NewExchangeServer(trustStore, tokenService, claimsFilterRegistry, credentialSources, obs)
	jwksServer := server.NewJWKSServer(server.JWKSServerConfig{
		IssuerRegistry: issuerRegistry,
		Observer:       obs,
	})

	if err := jwksServer.Start(ctx); err != nil {
		return fmt.Errorf("failed to start JWKS server: %w", err)
	}
	defer jwksServer.Stop()

	// 5. Create TCP listeners
	grpcListener, err := net.Listen("tcp", fmt.Sprintf(":%d", provider.GRPCPort()))
	if err != nil {
		return fmt.Errorf("failed to listen on gRPC port %d: %w", provider.GRPCPort(), err)
	}
	defer func() { _ = grpcListener.Close() }()

	httpListener, err := net.Listen("tcp", fmt.Sprintf(":%d", provider.HTTPPort()))
	if err != nil {
		return fmt.Errorf("failed to listen on HTTP port %d: %w", provider.HTTPPort(), err)
	}
	defer func() { _ = httpListener.Close() }()

	// 6. Create and start server
	srv := server.New(server.Config{
		GRPCListener:   grpcListener,
		HTTPListener:   httpListener,
		AuthzServer:    authzServer,
		ExchangeServer: exchangeServer,
		JWKSServer:     jwksServer,
		Observer:       obs,
		MuxConfigurer:  obs.ConfigureHTTPMux,
	})
	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	srv.SetReady()

	// 7. Log startup information
	grpcAddr := grpcListener.Addr().String()
	httpAddr := httpListener.Addr().String()
	logEvent := bootstrapLog.Info().
		Str("grpc_addr", grpcAddr).
		Str("http_addr", httpAddr).
		Str("token_exchange_url", "http://"+httpAddr+"/v1/token").
		Str("jwks_url", "http://"+httpAddr+"/v1/jwks.json").
		Str("jwks_wellknown_url", "http://"+httpAddr+"/.well-known/jwks.json").
		Str("health_grpc", grpcAddr+" (grpc.health.v1.Health)").
		Str("trust_domain", provider.TrustDomain()).
		Str("config", configPath)
	for k, v := range provider.BootstrapFields() {
		logEvent = logEvent.Str(k, v)
	}
	logEvent.Msg("parsec is running")

	// 8. Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	bootstrapLog.Info().Msg("Shutting down")

	// 9. Graceful shutdown
	// Flush observer resources (e.g. metrics) while the HTTP server is
	// still running so Prometheus can perform a final scrape.
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer shutdownCancel()
	if err := obs.Shutdown(shutdownCtx); err != nil {
		bootstrapLog.Warn().Err(err).Msg("observer shutdown error")
	}

	if err := srv.Stop(ctx); err != nil {
		return fmt.Errorf("error during shutdown: %w", err)
	}

	bootstrapLog.Info().Msg("Shutdown complete")
	return nil
}
