package config

import (
	"context"
	"fmt"
	"maps"
	"os"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
	"github.com/project-kessel/parsec/internal/issuer"
	"github.com/project-kessel/parsec/internal/keys"
	"github.com/project-kessel/parsec/internal/mapper"
	"github.com/project-kessel/parsec/internal/service"
)

// NewIssuerRegistry creates an issuer registry from configuration
func NewIssuerRegistry(cfg Config) (service.Registry, error) {
	registry := service.NewSimpleRegistry()

	// Build key provider registry from global config
	providerRegistry, err := buildKeyProviderRegistry(cfg.KeyProviders)
	if err != nil {
		return nil, fmt.Errorf("failed to build key provider registry: %w", err)
	}

	// Create shared key slot store
	slotStore := keys.NewInMemoryKeySlotStore()

	// Build signer registry from global config
	signerRegistry, err := buildSignerRegistry(cfg.Signers, cfg.TrustDomain, providerRegistry, slotStore)
	if err != nil {
		return nil, fmt.Errorf("failed to build signer registry: %w", err)
	}

	// Start all signers
	ctx := context.Background()
	if err := signerRegistry.Start(ctx); err != nil {
		return nil, fmt.Errorf("failed to start signers: %w", err)
	}

	for _, issuerCfg := range cfg.Issuers {
		if issuerCfg.TokenType == "" {
			return nil, fmt.Errorf("token_type is required for issuer")
		}

		// Use token type directly as service.TokenType (it's already a URN string)
		tokenType := service.TokenType(issuerCfg.TokenType)

		// Create issuer (now using signer registry instead of building signers inline)
		iss, err := newIssuer(issuerCfg, signerRegistry)
		if err != nil {
			return nil, fmt.Errorf("failed to create issuer for token type %s: %w", issuerCfg.TokenType, err)
		}

		// Register issuer
		registry.Register(tokenType, iss)
	}

	return registry, nil
}

// buildKeyProviderRegistry creates a map of KeyProvider instances from configuration
func buildKeyProviderRegistry(configs []KeyProviderConfig) (map[string]keys.KeyProvider, error) {
	registry := make(map[string]keys.KeyProvider)

	for _, cfg := range configs {
		if cfg.ID == "" {
			return nil, fmt.Errorf("key provider id is required")
		}

		if _, exists := registry[cfg.ID]; exists {
			return nil, fmt.Errorf("duplicate key provider id: %s", cfg.ID)
		}

		// Parse key type
		if cfg.KeyType == "" {
			return nil, fmt.Errorf("key provider %s requires key_type", cfg.ID)
		}
		keyType := keys.KeyType(cfg.KeyType)

		var provider keys.KeyProvider
		var err error

		switch cfg.Type {
		case "", "memory":
			provider = keys.NewInMemoryKeyProvider(keyType, cfg.Algorithm)

		case "disk":
			if cfg.KeysPath == "" {
				return nil, fmt.Errorf("disk key provider %s requires keys_path", cfg.ID)
			}
			provider, err = keys.NewDiskKeyProvider(keys.DiskKeyProviderConfig{
				KeyType:   keyType,
				Algorithm: cfg.Algorithm,
				KeysPath:  cfg.KeysPath,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create disk key provider %s: %w", cfg.ID, err)
			}

		case "aws_kms":
			if cfg.Region == "" {
				return nil, fmt.Errorf("aws_kms key provider %s requires region", cfg.ID)
			}
			if cfg.AliasPrefix == "" {
				return nil, fmt.Errorf("aws_kms key provider %s requires alias_prefix", cfg.ID)
			}
			provider, err = keys.NewAWSKMSKeyProvider(context.Background(), keys.AWSKMSConfig{
				KeyType:     keyType,
				Algorithm:   cfg.Algorithm,
				Region:      cfg.Region,
				AliasPrefix: cfg.AliasPrefix,
			})
			if err != nil {
				return nil, fmt.Errorf("failed to create aws_kms key provider %s: %w", cfg.ID, err)
			}

		default:
			return nil, fmt.Errorf("unknown key provider type for %s: %s (supported: memory, disk, aws_kms)", cfg.ID, cfg.Type)
		}

		registry[cfg.ID] = provider
	}

	return registry, nil
}

// buildSignerRegistry creates a SignerRegistry from configuration
func buildSignerRegistry(configs []SignerConfig, trustDomain string, providerRegistry map[string]keys.KeyProvider, slotStore keys.KeySlotStore) (*keys.SignerRegistry, error) {
	registry := keys.NewSignerRegistry()

	for _, cfg := range configs {
		if cfg.ID == "" {
			return nil, fmt.Errorf("signer id is required")
		}

		if cfg.KeyProviderID == "" {
			return nil, fmt.Errorf("signer %s requires key_provider_id", cfg.ID)
		}

		// Validate key provider exists
		if _, ok := providerRegistry[cfg.KeyProviderID]; !ok {
			return nil, fmt.Errorf("key provider not found for signer %s: %s", cfg.ID, cfg.KeyProviderID)
		}

		// Determine namespace (defaults to ID)
		namespace := cfg.Namespace
		if namespace == "" {
			namespace = cfg.ID
		}

		// Parse timing parameters
		keyTTL := 24 * time.Hour
		if cfg.KeyTTL != "" {
			duration, err := time.ParseDuration(cfg.KeyTTL)
			if err != nil {
				return nil, fmt.Errorf("invalid key_ttl for signer %s: %w", cfg.ID, err)
			}
			keyTTL = duration
		}

		rotationThreshold := 6 * time.Hour
		if cfg.RotationThreshold != "" {
			duration, err := time.ParseDuration(cfg.RotationThreshold)
			if err != nil {
				return nil, fmt.Errorf("invalid rotation_threshold for signer %s: %w", cfg.ID, err)
			}
			rotationThreshold = duration
		}

		gracePeriod := 2 * time.Hour
		if cfg.GracePeriod != "" {
			duration, err := time.ParseDuration(cfg.GracePeriod)
			if err != nil {
				return nil, fmt.Errorf("invalid grace_period for signer %s: %w", cfg.ID, err)
			}
			gracePeriod = duration
		}

		checkInterval := 1 * time.Minute
		if cfg.CheckInterval != "" {
			duration, err := time.ParseDuration(cfg.CheckInterval)
			if err != nil {
				return nil, fmt.Errorf("invalid check_interval for signer %s: %w", cfg.ID, err)
			}
			checkInterval = duration
		}

		prepareTimeout := 1 * time.Minute
		if cfg.PrepareTimeout != "" {
			duration, err := time.ParseDuration(cfg.PrepareTimeout)
			if err != nil {
				return nil, fmt.Errorf("invalid prepare_timeout for signer %s: %w", cfg.ID, err)
			}
			prepareTimeout = duration
		}

		// Create signer based on type
		var signer keys.RotatingSigner
		switch cfg.Type {
		case "", "dual_slot":
			signer = keys.NewDualSlotRotatingSigner(keys.DualSlotRotatingSignerConfig{
				Namespace:           namespace,
				TrustDomain:         trustDomain,
				KeyProviderID:       cfg.KeyProviderID,
				KeyProviderRegistry: providerRegistry,
				SlotStore:           slotStore,
				KeyTTL:              keyTTL,
				RotationThreshold:   rotationThreshold,
				GracePeriod:         gracePeriod,
				CheckInterval:       checkInterval,
				PrepareTimeout:      prepareTimeout,
			})
		default:
			return nil, fmt.Errorf("unknown signer type for %s: %s (supported: dual_slot)", cfg.ID, cfg.Type)
		}

		if err := registry.Register(cfg.ID, signer); err != nil {
			return nil, fmt.Errorf("failed to register signer %s: %w", cfg.ID, err)
		}
	}

	return registry, nil
}

// newIssuer creates an issuer from configuration
func newIssuer(cfg IssuerConfig, signerRegistry *keys.SignerRegistry) (service.Issuer, error) {
	switch cfg.Type {
	case "stub":
		return newStubIssuer(cfg)
	case "unsigned":
		return newUnsignedIssuer(cfg)
	case "transaction_token":
		return newTransactionTokenIssuer(cfg, signerRegistry)
	case "rh_identity":
		return newRHIdentityIssuer(cfg)
	default:
		return nil, fmt.Errorf("unknown issuer type: %s (supported: stub, unsigned, transaction_token, rh_identity)", cfg.Type)
	}
}

// newStubIssuer creates a stub issuer for testing
func newStubIssuer(cfg IssuerConfig) (service.Issuer, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("stub issuer requires issuer_url")
	}

	// Parse TTL
	ttl := 5 * time.Minute // default
	if cfg.TTL != "" {
		duration, err := time.ParseDuration(cfg.TTL)
		if err != nil {
			return nil, fmt.Errorf("invalid ttl: %w", err)
		}
		ttl = duration
	}

	// Create transaction context mappers
	var txnMappers []service.ClaimMapper
	for i, mapperCfg := range cfg.TransactionContextMappers {
		m, err := newClaimMapper(mapperCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create transaction context mapper %d: %w", i, err)
		}
		txnMappers = append(txnMappers, m)
	}

	// Create request context mappers
	var reqMappers []service.ClaimMapper
	for i, mapperCfg := range cfg.RequestContextMappers {
		m, err := newClaimMapper(mapperCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create request context mapper %d: %w", i, err)
		}
		reqMappers = append(reqMappers, m)
	}

	return issuer.NewStubIssuer(issuer.StubIssuerConfig{
		IssuerURL:                 cfg.IssuerURL,
		TTL:                       ttl,
		TransactionContextMappers: txnMappers,
		RequestContextMappers:     reqMappers,
	}), nil
}

// newTransactionTokenIssuer creates a transaction token issuer.
// This issuer signs transaction tokens using a signer from the global signer registry.
func newTransactionTokenIssuer(cfg IssuerConfig, signerRegistry *keys.SignerRegistry) (service.Issuer, error) {
	if cfg.IssuerURL == "" {
		return nil, fmt.Errorf("transaction_token issuer requires issuer_url")
	}

	// Validate signer_id is specified
	if cfg.SignerID == "" {
		return nil, fmt.Errorf("transaction_token issuer requires signer_id")
	}

	// Get signer from registry
	signer, err := signerRegistry.Get(cfg.SignerID)
	if err != nil {
		return nil, fmt.Errorf("signer not found: %s", cfg.SignerID)
	}

	// Parse TTL
	ttl := 5 * time.Minute // default
	if cfg.TTL != "" {
		duration, err := time.ParseDuration(cfg.TTL)
		if err != nil {
			return nil, fmt.Errorf("invalid ttl: %w", err)
		}
		ttl = duration
	}

	// Create transaction context mappers
	var txnMappers []service.ClaimMapper
	for i, mapperCfg := range cfg.TransactionContextMappers {
		m, err := newClaimMapper(mapperCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create transaction context mapper %d: %w", i, err)
		}
		txnMappers = append(txnMappers, m)
	}

	// Create request context mappers
	var reqMappers []service.ClaimMapper
	for i, mapperCfg := range cfg.RequestContextMappers {
		m, err := newClaimMapper(mapperCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create request context mapper %d: %w", i, err)
		}
		reqMappers = append(reqMappers, m)
	}

	return issuer.NewTransactionTokenIssuer(issuer.TransactionTokenIssuerConfig{
		IssuerURL:                 cfg.IssuerURL,
		TTL:                       ttl,
		Signer:                    signer,
		TransactionContextMappers: txnMappers,
		RequestContextMappers:     reqMappers,
	}), nil
}

// newUnsignedIssuer creates an unsigned issuer (for development/testing)
func newUnsignedIssuer(cfg IssuerConfig) (service.Issuer, error) {
	// Create claim mappers
	var mappers []service.ClaimMapper
	for i, mapperCfg := range cfg.ClaimMappers {
		m, err := newClaimMapper(mapperCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create claim mapper %d: %w", i, err)
		}
		mappers = append(mappers, m)
	}

	return issuer.NewUnsignedIssuer(issuer.UnsignedIssuerConfig{
		TokenType:    cfg.TokenType,
		ClaimMappers: mappers,
	}), nil
}

// newRHIdentityIssuer creates a Red Hat identity issuer
func newRHIdentityIssuer(cfg IssuerConfig) (service.Issuer, error) {
	// Create claim mappers
	var mappers []service.ClaimMapper
	for i, mapperCfg := range cfg.ClaimMappers {
		m, err := newClaimMapper(mapperCfg)
		if err != nil {
			return nil, fmt.Errorf("failed to create claim mapper %d: %w", i, err)
		}
		mappers = append(mappers, m)
	}

	return issuer.NewRHIdentityIssuer(issuer.RHIdentityIssuerConfig{
		TokenType:    cfg.TokenType,
		ClaimMappers: mappers,
	}), nil
}

// newClaimMapper creates a claim mapper from configuration
func newClaimMapper(cfg ClaimMapperConfig) (service.ClaimMapper, error) {
	switch cfg.Type {
	case "cel":
		return newCELMapper(cfg)
	case "passthrough":
		return service.NewPassthroughSubjectMapper(), nil
	case "request_attributes":
		return service.NewRequestAttributesMapper(), nil
	case "stub":
		return newStubMapper(cfg)
	default:
		return nil, fmt.Errorf("unknown claim mapper type: %s (supported: cel, passthrough, request_attributes, stub)", cfg.Type)
	}
}

// newCELMapper creates a CEL-based claim mapper
func newCELMapper(cfg ClaimMapperConfig) (service.ClaimMapper, error) {
	script := cfg.Script

	// Load from file if script_file is specified
	if cfg.ScriptFile != "" {
		content, err := os.ReadFile(cfg.ScriptFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read script file %s: %w", cfg.ScriptFile, err)
		}
		script = string(content)
	}

	if script == "" {
		return nil, fmt.Errorf("cel mapper requires script or script_file")
	}

	return mapper.NewCELMapper(script)
}

// newStubMapper creates a stub claim mapper that returns fixed claims
func newStubMapper(cfg ClaimMapperConfig) (service.ClaimMapper, error) {
	if cfg.Claims == nil {
		return nil, fmt.Errorf("stub mapper requires claims")
	}

	// Convert map[string]any to claims.Claims
	fixedClaims := claims.Claims(maps.Clone(cfg.Claims))

	return service.NewStubClaimMapper(fixedClaims), nil
}
