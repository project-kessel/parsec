package config

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/project-kessel/parsec/internal/datasource"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/service"
)

// NewDataSourceRegistry creates a data source registry from configuration
func NewDataSourceRegistry(cfg []DataSourceConfig, transport http.RoundTripper) (*service.DataSourceRegistry, error) {
	registry := service.NewDataSourceRegistry()

	for _, dsCfg := range cfg {
		ds, err := newDataSource(dsCfg, transport)
		if err != nil {
			return nil, fmt.Errorf("failed to create data source %s: %w", dsCfg.Name, err)
		}
		registry.Register(ds)
	}

	return registry, nil
}

// newDataSource creates a data source from configuration
func newDataSource(cfg DataSourceConfig, transport http.RoundTripper) (service.DataSource, error) {
	switch cfg.Type {
	case "lua":
		return newLuaDataSource(cfg, transport)
	default:
		return nil, fmt.Errorf("unknown data source type: %s (supported: lua)", cfg.Type)
	}
}

// newLuaDataSource creates a Lua data source with optional caching
func newLuaDataSource(cfg DataSourceConfig, transport http.RoundTripper) (service.DataSource, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("data source name is required")
	}

	// Get script content (either from file or inline)
	script := cfg.Script
	if cfg.ScriptFile != "" {
		content, err := os.ReadFile(cfg.ScriptFile)
		if err != nil {
			return nil, fmt.Errorf("failed to read script file %s: %w", cfg.ScriptFile, err)
		}
		script = string(content)
	}

	if script == "" {
		return nil, fmt.Errorf("lua data source requires either script or script_file")
	}

	// Create config source from map
	var configSource luaservices.ConfigSource
	if cfg.Config != nil {
		configSource = luaservices.NewMapConfigSource(cfg.Config)
	}

	// Build HTTP config
	var httpConfig *luaservices.HTTPServiceConfig
	if cfg.HTTPConfig != nil {
		httpCfg, err := buildHTTPConfig(cfg.HTTPConfig, transport)
		if err != nil {
			return nil, fmt.Errorf("failed to build HTTP config: %w", err)
		}
		httpConfig = httpCfg
	}

	// Create base Lua data source
	luaDSConfig := datasource.LuaDataSourceConfig{
		Name:         cfg.Name,
		Script:       script,
		ConfigSource: configSource,
		HTTPConfig:   httpConfig,
	}

	baseDS, err := datasource.NewLuaDataSource(luaDSConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create lua data source: %w", err)
	}

	// Wrap with caching if configured
	if cfg.Caching != nil {
		return wrapWithCaching(baseDS, *cfg.Caching)
	}

	return baseDS, nil
}

// buildHTTPConfig creates an HTTPServiceConfig from the config structure
func buildHTTPConfig(cfg *HTTPConfig, transport http.RoundTripper) (*luaservices.HTTPServiceConfig, error) {
	httpServiceCfg := &luaservices.HTTPServiceConfig{}

	// Parse timeout
	if cfg.Timeout != "" {
		duration, err := time.ParseDuration(cfg.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid http timeout: %w", err)
		}
		httpServiceCfg.Timeout = duration
	} else {
		httpServiceCfg.Timeout = 30 * time.Second // default
	}

	// Use the provided HTTP transport (from top-level config)
	if transport != nil {
		httpServiceCfg.Transport = transport
	}

	return httpServiceCfg, nil
}

// wrapWithCaching wraps a data source with the configured caching layer
func wrapWithCaching(ds service.DataSource, cfg CachingConfig) (service.DataSource, error) {
	switch cfg.Type {
	case "in_memory":
		// In-memory caching uses the Cacheable interface from the data source
		return datasource.NewInMemoryCachingDataSource(ds), nil

	case "distributed":
		groupName := cfg.GroupName
		if groupName == "" {
			groupName = ds.Name() + "-cache"
		}

		cacheSize := cfg.CacheSize
		if cacheSize == 0 {
			cacheSize = 64 << 20 // 64 MB default
		}

		cachingCfg := datasource.DistributedCachingConfig{
			GroupName:      groupName,
			CacheSizeBytes: cacheSize,
		}

		return datasource.NewDistributedCachingDataSource(ds, cachingCfg), nil

	case "none", "":
		// No caching
		return ds, nil

	default:
		return nil, fmt.Errorf("unknown caching type: %s (supported: in_memory, distributed, none)", cfg.Type)
	}
}
