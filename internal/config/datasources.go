package config

import (
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/project-kessel/parsec/internal/datasource"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/observer"
	"github.com/project-kessel/parsec/internal/service"
)

// NewDataSourceRegistry creates a data source registry from configuration.
// The observer provides cache lifecycle events for data sources that use caching.
func NewDataSourceRegistry(cfg []DataSourceConfig, transport http.RoundTripper, obs observer.Observer) (*service.DataSourceRegistry, error) {
	registry := service.NewDataSourceRegistry()

	for _, dsCfg := range cfg {
		ds, err := newDataSource(dsCfg, transport, obs)
		if err != nil {
			return nil, fmt.Errorf("failed to create data source %s: %w", dsCfg.Name, err)
		}
		registry.Register(ds)
	}

	return registry, nil
}

func newDataSource(cfg DataSourceConfig, transport http.RoundTripper, obs observer.Observer) (service.DataSource, error) {
	switch cfg.Type {
	case "lua":
		return newLuaDataSource(cfg, transport, obs)
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

func newLuaDataSource(cfg DataSourceConfig, transport http.RoundTripper, obs observer.Observer) (service.DataSource, error) {
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

	// Build HTTP options
	var httpOptions []luaservices.HTTPServiceOption
	if cfg.HTTPConfig != nil {
		opts, err := buildHTTPOptions(cfg.HTTPConfig, transport)
		if err != nil {
			return nil, fmt.Errorf("failed to build HTTP options: %w", err)
		}
		httpOptions = opts
	}

	var baseDS service.DataSource

	if cfg.CacheKeyFunc != "" {
		var cacheTTL time.Duration
		if cfg.LuaCacheTTL != "" {
			var err error
			cacheTTL, err = time.ParseDuration(cfg.LuaCacheTTL)
			if err != nil {
				return nil, fmt.Errorf("invalid lua_cache_ttl: %w", err)
			}
		}

		cacheable, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
			Name:         cfg.Name,
			Script:       script,
			ConfigSource: configSource,
			HTTPOptions:  httpOptions,
			Observer:     obs,
			CacheKeyFunc: cfg.CacheKeyFunc,
			CacheTTL:     cacheTTL,
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
			HTTPOptions:  httpOptions,
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

func buildHTTPOptions(cfg *HTTPConfig, transport http.RoundTripper) ([]luaservices.HTTPServiceOption, error) {
	var opts []luaservices.HTTPServiceOption

	if cfg.Timeout != "" {
		duration, err := time.ParseDuration(cfg.Timeout)
		if err != nil {
			return nil, fmt.Errorf("invalid http timeout: %w", err)
		}
		opts = append(opts, luaservices.WithTimeout(duration))
	}

	if transport != nil {
		opts = append(opts, luaservices.WithTransport(transport))
	}

	return opts, nil
}

// wrapWithCaching wraps a data source with the configured caching layer.
// This is the coupling point where the central observer is narrowed to
// the cache-specific CacheObserver sub-interface.
func wrapWithCaching(ds service.DataSource, cfg CachingConfig, obs observer.Observer) (service.DataSource, error) {
	switch cfg.Type {
	case "in_memory":
		return datasource.NewInMemoryCachingDataSource(ds, obs), nil

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
