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

// NewStaticDataSource creates a data source that always returns data.
func NewStaticDataSource(name string, data map[string]any) (service.DataSource, error) {
	if name == "" {
		return nil, fmt.Errorf("name is required")
	}
	if data == nil {
		return nil, fmt.Errorf("data is required")
	}

	cloned := maps.Clone(data)
	marshaled, err := json.Marshal(cloned)
	if err != nil {
		return nil, fmt.Errorf("marshal static data: %w", err)
	}

	return &StaticDataSource{
		name:          name,
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
