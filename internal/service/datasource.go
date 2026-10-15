package service

import (
	"context"

	"github.com/project-kessel/parsec/internal/request"
	"github.com/project-kessel/parsec/internal/trust"
)

// DataSource provides additional data for token context building
// Data sources can fetch information from external systems (databases, APIs, etc.)
// to enrich the token context.
type DataSource interface {
	// Name identifies this data source.
	// The name is used as a key for lookups in the registry.
	Name() string

	// Fetch retrieves data based on the input.
	// Returns serialized data to avoid unnecessary serialization/deserialization.
	// If the data source fetches from a remote API that returns JSON,
	// it can return the raw JSON bytes directly without deserializing first.
	//
	// Returns nil result and nil error if the data source has nothing to contribute.
	// Returns non-nil error only for fatal errors that should fail token issuance.
	Fetch(ctx context.Context, input *DataSourceInput) (*DataSourceResult, error)
}

// Cacheable is an optional interface that data sources can implement
// to enable caching of their results.
type Cacheable interface {
	// CacheKey returns a masked copy of the input with only the fields that affect the result,
	// and whether this request should use the cache at all.
	//
	// When useCache is false, wrappers must Fetch with the original input and must not
	// read or write cache entries. Lua scripts signal this by returning nil from
	// fetch_cache_key.
	//
	// When useCache is true:
	//  1. The returned input is the cache key (after serialization)
	//  2. Distributed wrappers also pass that input to Fetch on a miss — it must
	//     contain all data needed for Fetch
	//
	// Fields that don't affect the result should be zeroed out to reduce cache key size.
	// ctx is bound to any Lua VM so cache-key scripts abort on cancellation.
	CacheKey(ctx context.Context, input *DataSourceInput) (key DataSourceInput, useCache bool)
}

// DataSourceContentType identifies the serialization format of data source results
type DataSourceContentType string

const (
	// ContentTypeJSON indicates the data is JSON-encoded
	ContentTypeJSON DataSourceContentType = "application/json"
)

// DataSourceResult contains serialized data from a data source
type DataSourceResult struct {
	// Data is the serialized data (e.g., JSON bytes).
	// Callers must treat Data as read-only and must not modify the slice in place.
	Data []byte

	// ContentType identifies how to deserialize the data
	ContentType DataSourceContentType
}

// DataSourceInput contains the inputs available to a data source
// All fields are exported and JSON-serializable for easy debugging and caching
//
// Example JSON serialization:
//
//	input := &DataSourceInput{
//	    Subject: &trust.Result{
//	        Subject: "user@example.com",
//	        Issuer: "https://idp.example.com",
//	    },
//	}
//	jsonBytes, _ := json.Marshal(input)
//	// {"subject":{"subject":"user@example.com","issuer":"https://idp.example.com"}}
//
//	var decoded DataSourceInput
//	json.Unmarshal(jsonBytes, &decoded)
type DataSourceInput struct {
	// Subject identity (attested claims from validated credential)
	Subject *trust.Result `json:"subject,omitempty"`

	// Actor identity (attested claims from actor credential)
	Actor *trust.Result `json:"actor,omitempty"`

	// RequestAttributes contains information about the request
	RequestAttributes *request.RequestAttributes `json:"request_attributes,omitempty"`
}

// DataSourceRegistry is a simple registry that stores data sources by name
type DataSourceRegistry struct {
	sources map[string]DataSource
}

// NewDataSourceRegistry creates a new data source registry
func NewDataSourceRegistry() *DataSourceRegistry {
	return &DataSourceRegistry{
		sources: make(map[string]DataSource),
	}
}

// Register adds a data source to the registry
func (r *DataSourceRegistry) Register(source DataSource) {
	r.sources[source.Name()] = source
}

// Get retrieves a data source by name
// Returns nil if the data source is not found
func (r *DataSourceRegistry) Get(name string) DataSource {
	return r.sources[name]
}

// Names returns the names of all registered data sources
func (r *DataSourceRegistry) Names() []string {
	names := make([]string, 0, len(r.sources))
	for name := range r.sources {
		names = append(names, name)
	}
	return names
}
