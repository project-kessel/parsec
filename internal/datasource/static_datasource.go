package datasource

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"

	"github.com/project-kessel/parsec/internal/service"
)

// StaticDataSource returns fixed JSON data on every fetch.
type StaticDataSource struct {
	name string
	data map[string]any
}

// StaticDataSourceConfig configures a static data source.
type StaticDataSourceConfig struct {
	Name string
	Data map[string]any
}

// NewStaticDataSource creates a data source that always returns the configured data.
func NewStaticDataSource(cfg StaticDataSourceConfig) (service.DataSource, error) {
	if cfg.Name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if cfg.Data == nil {
		return nil, fmt.Errorf("data is required")
	}
	return &StaticDataSource{
		name: cfg.Name,
		data: maps.Clone(cfg.Data),
	}, nil
}

func (s *StaticDataSource) Name() string {
	return s.name
}

func (s *StaticDataSource) Fetch(context.Context, *service.DataSourceInput) (*service.DataSourceResult, error) {
	data, err := json.Marshal(s.data)
	if err != nil {
		return nil, fmt.Errorf("marshal static data: %w", err)
	}
	return &service.DataSourceResult{
		Data:        data,
		ContentType: service.ContentTypeJSON,
	}, nil
}
