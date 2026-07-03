package config

import (
	"fmt"
	"os"
	"time"

	"github.com/project-kessel/parsec/internal/datasource"
	"github.com/project-kessel/parsec/internal/httpclient"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/observer"
	"github.com/project-kessel/parsec/internal/service"
)

const defaultCacheTTL = 5 * time.Minute

// NewDataSourceRegistry creates a data source registry from configuration.
// The observer provides cache lifecycle events for data sources that use caching.
func NewDataSourceRegistry(cfg []DataSourceConfig, httpRegistry *httpclient.Registry, obs observer.Observer) (*service.DataSourceRegistry, error) {
	registry := service.NewDataSourceRegistry()

	for _, dsCfg := range cfg {
		ds, err := newDataSource(dsCfg, httpRegistry, obs)
		if err != nil {
			return nil, fmt.Errorf("failed to create data source %s: %w", dsCfg.Name, err)
		}
		registry.Register(ds)
	}

	return registry, nil
}

func newDataSource(cfg DataSourceConfig, httpRegistry *httpclient.Registry, obs observer.Observer) (service.DataSource, error) {
	switch cfg.Type {
	case "lua":
		return newLuaDataSource(cfg, httpRegistry, obs)
	case "static":
		return newStaticDataSource(cfg)
	default:
		return nil, fmt.Errorf("unknown data source type: %s (supported: lua, static)", cfg.Type)
	}
}

func newStaticDataSource(cfg DataSourceConfig) (service.DataSource, error) {
	if cfg.Data == nil {
		return nil, fmt.Errorf("static data source requires data")
	}
	return datasource.NewStaticDataSource(cfg.Name, cfg.Data)
}

func newLuaDataSource(cfg DataSourceConfig, httpRegistry *httpclient.Registry, obs observer.Observer) (service.DataSource, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("data source name is required")
	}

	script, err := readScript(cfg.Script, cfg.ScriptFile)
	if err != nil {
		return nil, err
	}
	if script == "" {
		return nil, fmt.Errorf("lua data source requires either script or script_file")
	}

	// Create config source from map
	var configSource luaservices.ConfigSource
	if cfg.Config != nil {
		configSource = luaservices.NewMapConfigSource(cfg.Config)
	}

	// Resolve HTTP client from registry
	client, err := resolveHTTPClient(cfg.HTTPClient, cfg.HTTPClientSpec, httpRegistry)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve HTTP client: %w", err)
	}

	var baseDS service.DataSource

	if cachingEnabled(cfg.Caching) {
		cacheable, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
			Name:         cfg.Name,
			Script:       script,
			ConfigSource: configSource,
			HTTPClient:   client,
			Observer:     obs,
		})
		if err != nil {
			return nil, fmt.Errorf("failed to create cacheable lua data source: %w", err)
		}
		baseDS = cacheable
	} else {
		luaDSConfig := datasource.LuaDataSourceConfig{
			Name:         cfg.Name,
			Script:       script,
			ConfigSource: configSource,
			HTTPClient:   client,
			Observer:     obs,
		}

		var err error
		baseDS, err = datasource.NewLuaDataSource(luaDSConfig)
		if err != nil {
			return nil, fmt.Errorf("failed to create lua data source: %w", err)
		}
	}

	if cfg.Caching != nil {
		return wrapWithCaching(baseDS, *cfg.Caching, obs)
	}

	return baseDS, nil
}

func readScript(inline, file string) (string, error) {
	if file == "" {
		return inline, nil
	}
	content, err := os.ReadFile(file)
	if err != nil {
		return "", fmt.Errorf("failed to read script file %s: %w", file, err)
	}
	return string(content), nil
}

func cachingEnabled(cfg *CachingConfig) bool {
	if cfg == nil {
		return false
	}
	switch cfg.Type {
	case "in_memory", "distributed":
		return true
	default:
		return false
	}
}

func parseCacheTTL(cfg *CachingConfig) (time.Duration, error) {
	if cfg == nil || cfg.TTL == "" {
		return defaultCacheTTL, nil
	}
	duration, err := time.ParseDuration(cfg.TTL)
	if err != nil {
		return 0, fmt.Errorf("invalid cache ttl: %w", err)
	}
	return duration, nil
}

// wrapWithCaching wraps a data source with the configured caching layer.
// This is the coupling point where the central observer is narrowed to
// the cache-specific CacheObserver sub-interface.
func wrapWithCaching(ds service.DataSource, cfg CachingConfig, obs observer.Observer) (service.DataSource, error) {
	cacheTTL, err := parseCacheTTL(&cfg)
	if err != nil {
		return nil, err
	}

	switch cfg.Type {
	case "in_memory":
		return datasource.NewInMemoryCachingDataSource(ds, obs,
			datasource.WithCacheTTL(cacheTTL),
		), nil

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
			CacheTTL:       cacheTTL,
		}

		return datasource.NewDistributedCachingDataSource(ds, cachingCfg), nil

	case "none", "":
		// No caching
		return ds, nil

	default:
		return nil, fmt.Errorf("unknown caching type: %s (supported: in_memory, distributed, none)", cfg.Type)
	}
}
