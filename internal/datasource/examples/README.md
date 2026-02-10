# LuaDataSource Examples

This directory contains example Lua scripts demonstrating various use cases for the LuaDataSource.

## Examples

### 1. user_data.lua

Basic example demonstrating:
- Reading configuration values
- Making HTTP GET requests with headers
- Parsing JSON responses
- Error handling
- Enriching response data
- Cache key generation

**Use Case**: Fetch user profile data from an external API.

**Configuration Required**:
```go
Config: map[string]interface{}{
    "api_endpoint": "https://api.example.com",
    "api_key": "your-api-key",
}
```

### 2. multi_source.lua

Advanced example demonstrating:
- Conditional logic based on user type
- Multiple HTTP calls
- Data merging from multiple sources
- Helper functions for common operations
- Different data paths for different user types

**Use Case**: Fetch different data based on user type (admin, service, standard).

**Configuration Required**:
```go
Config: map[string]interface{}{
    "api_endpoint": "https://api.example.com",
    "api_key": "your-api-key",
}
```

### 3. regional_data.lua

Regional routing example demonstrating:
- Using request attributes (headers)
- Building dynamic URLs
- Fallback logic for errors
- Region-aware caching

**Use Case**: Fetch data from region-specific endpoints based on request headers.

**Configuration Required**:
```go
Config: map[string]interface{}{
    "api_endpoint": "https://api.example.com",
    "api_key": "your-api-key",
}
```

## Using These Examples

### In Go Code

```go
package main

import (
    "io/ioutil"
    "time"
    "github.com/project-kessel/parsec/internal/datasource"
)

func main() {
    // Read script from file
    script, err := ioutil.ReadFile("examples/user_data.lua")
    if err != nil {
        panic(err)
    }
    
    // Create data source
    ds, err := datasource.NewLuaDataSource(datasource.LuaDataSourceConfig{
        Name:        "user-data",
        Script:      string(script),
        Config: map[string]interface{}{
            "api_endpoint": "https://api.example.com",
            "api_key":      "secret123",
        },
        HTTPTimeout: 30 * time.Second,
        Cacheable:   true,
        CacheKeyFunc: "cache_key",
        CacheTTL:    5 * time.Minute,
    })
    if err != nil {
        panic(err)
    }
    
    // Use the data source
    // ...
}
```

### With Caching

```go
// Wrap with in-memory caching
cachedDS := datasource.NewInMemoryCachingDataSource(ds)

// Or with distributed caching
cachedDS := datasource.NewDistributedCachingDataSource(ds, 
    datasource.DistributedCachingConfig{
        GroupName:      "user-data",
        CacheSizeBytes: 64 << 20,  // 64MB
    })
```

## Testing Your Scripts

You can test your Lua scripts using the test files as examples:

```go
func TestMyLuaScript(t *testing.T) {
    script := `
    function fetch(input)
        -- Your script here
    end
    `
    
    ds, err := datasource.NewLuaDataSource(datasource.LuaDataSourceConfig{
        Name:   "test",
        Script: script,
        Config: map[string]interface{}{
            "api_key": "test-key",
        },
    })
    if err != nil {
        t.Fatal(err)
    }
    
    input := &issuer.DataSourceInput{
        Subject: &trust.Result{
            Subject: "test@example.com",
        },
    }
    
    result, err := ds.Fetch(context.Background(), input)
    // Assert results...
}
```

## Common Patterns

### 1. Error Handling

```lua
-- Fatal errors (fail token issuance)
if api_key == nil then
    error("api_key is required")
end

-- Non-fatal errors (return nil)
if response.status == 404 then
    return nil
end
```

### 2. Response Validation

```lua
local data, err = json.decode(response.body)
if data == nil then
    error("Invalid JSON: " .. err)
end

if data.id == nil then
    error("Response missing required field: id")
end
```

### 3. Conditional Fetching

```lua
function fetch(input)
    if input.subject.claims.premium then
        return fetch_premium_data(input)
    else
        return fetch_standard_data(input)
    end
end
```

### 4. Multiple API Calls

```lua
function fetch(input)
    local profile = fetch_api("/profile")
    local settings = fetch_api("/settings")
    
    if profile == nil or settings == nil then
        return nil
    end
    
    local result = {
        profile = profile,
        settings = settings
    }
    
    return {
        data = json.encode(result),
        content_type = "application/json"
    }
end
```

### 5. Dynamic URLs

```lua
local url = string.format("%s/users/%s/data", base_url, subject)
local url = base_url .. "/users/" .. subject .. "/data"
```

## Best Practices

1. **Validate Config**: Check for required config values at the start of fetch()
2. **Handle Errors Gracefully**: Use error() for fatal errors, return nil for non-fatal
3. **Add Context**: Enrich response data with metadata (fetched_at, source, etc.)
4. **Use Helper Functions**: Extract common logic into helper functions
5. **Cache Wisely**: Only include fields in cache_key that affect the result
6. **Log Debug Info**: Use print() to output debug information
7. **Test Thoroughly**: Write tests for your scripts before deployment

## Troubleshooting

### Script Won't Load
- Check Lua syntax
- Ensure fetch() function is defined
- Verify cache_key() function exists if CacheKeyFunc is set

### HTTP Errors
- Check API endpoint configuration
- Verify API key is correct
- Ensure timeout is sufficient
- Check network connectivity

### JSON Errors
- Validate API response is valid JSON
- Check for empty responses
- Handle null values appropriately

### Cache Issues
- Verify cache_key() returns consistent results
- Ensure cache_key() includes all relevant fields
- Check TTL is appropriate for your use case

## Additional Resources

- [LUA_DATASOURCE.md](../LUA_DATASOURCE.md) - Full documentation
- [internal/lua/README.md](../../lua/README.md) - Lua services documentation
- Test files in `internal/datasource/lua_datasource_test.go` for more examples

