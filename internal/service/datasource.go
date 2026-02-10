package service

import (
	"context"
	"time"

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
// to enable caching of their results
type Cacheable interface {
	// CacheKey returns a masked copy of the input with only the fields that affect the result.
	// This serves two purposes:
	// 1. It's the cache key (after serialization) - only relevant fields are included
	// 2. It's the input used to fetch on cache miss - it contains all data needed for Fetch
	//
	// Fields that don't affect the result should be zeroed out to reduce cache key size.
	// For example, if only Subject.Subject matters, return an input with just that field set.
	//
	// The returned input MUST be sufficient to call Fetch() if there's a cache miss.
	// Returned by value for clear semantics - it's a derived value, not a shared reference.
	CacheKey(input *DataSourceInput) DataSourceInput

	// CacheTTL returns the time-to-live for cached entries.
	// The actual TTL may vary. This is a hint.
	// In general, values should last for at _most_ the TTL.
	//
	// Return 0 to disable TTL-based expiration (cache indefinitely).
	CacheTTL() time.Duration
}

// DataSourceContentType identifies the serialization format of data source results
type DataSourceContentType string

const (
	// ContentTypeJSON indicates the data is JSON-encoded
	ContentTypeJSON DataSourceContentType = "application/json"
)

// DataSourceResult contains serialized data from a data source
type DataSourceResult struct {
	// Data is the serialized data (e.g., JSON bytes)
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
