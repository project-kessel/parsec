package cli

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

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

	// 1. Determine config file path
	configPath := configFile
	if configPath == "" {
		// Check environment variable
		configPath = os.Getenv("PARSEC_CONFIG")
	}
	// If still empty, configPath remains empty and we'll use env vars/flags only

	// 2. Load configuration (file + env vars + flags)
	loader, err := config.NewLoaderWithFlags(configPath, cmd.Flags())
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}

	cfg, err := loader.Get()
	if err != nil {
		return fmt.Errorf("failed to parse config: %w", err)
	}

	// 3. Create provider to build all components from config
	provider := config.NewProvider(cfg)

	// 4. Build components via provider
	trustStore, err := provider.TrustStore()
	if err != nil {
		return fmt.Errorf("failed to create trust store: %w", err)
	}

	tokenService, err := provider.TokenService()
	if err != nil {
		return fmt.Errorf("failed to create token service: %w", err)
	}

	// 5. Get authz server token types from config
	authzTokenTypes, err := provider.AuthzServerTokenTypes()
	if err != nil {
		return fmt.Errorf("failed to get authz token types: %w", err)
	}

	// Get exchange server claims filter registry from config
	claimsFilterRegistry, err := provider.ExchangeServerClaimsFilterRegistry()
	if err != nil {
		return fmt.Errorf("failed to get exchange server claims filter registry: %w", err)
	}

	// Get issuer registry for JWKS endpoint
	issuerRegistry, err := provider.IssuerRegistry()
	if err != nil {
		return fmt.Errorf("failed to get issuer registry: %w", err)
	}

	// Get observer for observability
	observer, err := provider.Observer()
	if err != nil {
		return fmt.Errorf("failed to get observer: %w", err)
	}

	// 6. Create service handlers with observability
	authzServer := server.NewAuthzServer(trustStore, tokenService, authzTokenTypes, observer)
	exchangeServer := server.NewExchangeServer(trustStore, tokenService, claimsFilterRegistry, observer)
	jwksServer := server.NewJWKSServer(server.JWKSServerConfig{
		IssuerRegistry: issuerRegistry,
		// Use default refresh interval (1 minute)
	})

	// Start JWKS background refresh
	if err := jwksServer.Start(ctx); err != nil {
		return fmt.Errorf("failed to start JWKS server: %w", err)
	}
	defer jwksServer.Stop()

	// 7. Create server configuration
	serverCfg := provider.ServerConfig()
	serverCfg.AuthzServer = authzServer
	serverCfg.ExchangeServer = exchangeServer
	serverCfg.JWKSServer = jwksServer

	// 8. Create and start server
	srv := server.New(serverCfg)
	if err := srv.Start(ctx); err != nil {
		return fmt.Errorf("failed to start server: %w", err)
	}

	fmt.Println("parsec is running")
	fmt.Printf("  gRPC (ext_authz):      localhost:%d\n", serverCfg.GRPCPort)
	fmt.Printf("  HTTP (token exchange): http://localhost:%d/v1/token\n", serverCfg.HTTPPort)
	fmt.Printf("  HTTP (JWKS):           http://localhost:%d/v1/jwks.json\n", serverCfg.HTTPPort)
	fmt.Printf("                         http://localhost:%d/.well-known/jwks.json\n", serverCfg.HTTPPort)
	fmt.Printf("  Trust Domain:          %s\n", provider.TrustDomain())
	fmt.Printf("  Config:                %s\n", configPath)

	// 9. Wait for interrupt signal
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	<-sigCh

	fmt.Println("\nShutting down...")

	// 10. Graceful shutdown
	if err := srv.Stop(ctx); err != nil {
		return fmt.Errorf("error during shutdown: %w", err)
	}

	fmt.Println("Shutdown complete")
	return nil
}
