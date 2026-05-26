package datasource

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"slices"

	"github.com/project-kessel/parsec/internal/service"
)

// StaticDataSource returns fixed JSON data on every fetch.
type StaticDataSource struct {
	name          string
	marshaledData []byte
}

type staticConfig struct {
	name string
	data map[string]any
}

// StaticDataSourceOption configures a StaticDataSource.
type StaticDataSourceOption func(*staticConfig)

// WithStaticName sets the data source name.
func WithStaticName(name string) StaticDataSourceOption {
	return func(cfg *staticConfig) {
		cfg.name = name
	}
}

// WithStaticData sets the fixed data returned on every fetch.
func WithStaticData(data map[string]any) StaticDataSourceOption {
	return func(cfg *staticConfig) {
		cfg.data = data
	}
}

// NewStaticDataSource creates a data source that always returns the configured data.
func NewStaticDataSource(opts ...StaticDataSourceOption) (service.DataSource, error) {
	cfg := &staticConfig{}
	for _, opt := range opts {
		opt(cfg)
	}
	if cfg.name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if cfg.data == nil {
		return nil, fmt.Errorf("data is required")
	}

	cloned := maps.Clone(cfg.data)
	marshaled, err := json.Marshal(cloned)
	if err != nil {
		return nil, fmt.Errorf("marshal static data: %w", err)
	}

	return &StaticDataSource{
		name:          cfg.name,
		marshaledData: marshaled,
	}, nil
}

func (s *StaticDataSource) Name() string {
	return s.name
}

func (s *StaticDataSource) Fetch(context.Context, *service.DataSourceInput) (*service.DataSourceResult, error) {
	return &service.DataSourceResult{
		Data:        slices.Clone(s.marshaledData),
		ContentType: service.ContentTypeJSON,
	}, nil
}
