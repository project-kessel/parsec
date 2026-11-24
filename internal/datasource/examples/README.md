# LuaDataSource Examples

This directory contains example Lua scripts demonstrating various use cases for the LuaDataSource.

Scripts run in a sandbox with only the `base`, `table`, `string`, and `math`
standard libraries. `os`, `io`, and `debug` are not available. The examples
are exercised by `lua_datasource_examples_test.go`, so they must keep working
inside the sandbox. See [Security Model](../LUA_DATASOURCE.md#security-model).

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

**Configuration Required**: an HTTP client with `base_url` (and usually
`http_auth`). The script builds only a relative path with `url.path_escape()`.
See the header comment in `user_data.lua` for a YAML example.

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

**Configuration Required**: an HTTP client with `base_url` (and usually
`http_auth`). The region header and subject are escaped with `url.path_escape()`.

## Using These Examples

### In Go Code

```go
package main

import (
    "io/ioutil"
    "net/http"
    "time"
    "github.com/project-kessel/parsec/internal/datasource"
    "github.com/project-kessel/parsec/internal/httpclient"
    luaservices "github.com/project-kessel/parsec/internal/lua"
)

func main() {
    // Read script from file
    script, err := ioutil.ReadFile("examples/user_data.lua")
    if err != nil {
        panic(err)
    }
    
    configSource := luaservices.NewMapConfigSource(map[string]interface{}{
        "api_endpoint": "https://api.example.com",
        "api_key":      "secret123",
    })

    // Create cacheable data source. The script must define fetch_cache_key(input).
    ds, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
        Name:         "user-data",
        Script:       string(script),
        ConfigSource: configSource,
        HTTP: httpclient.LuaClient{
            Client:  &http.Client{Timeout: 30 * time.Second},
            BaseURL: "https://api.example.com",
        },
        MaxResponseBytes: 64 << 10, // optional; default 1 MiB
        RequestOptions: func(req *http.Request) error {
            apiKey, _ := configSource.Get("api_key")
            req.Header.Set("Authorization", "Bearer "+apiKey.(string))
            return nil
        },
    })
    if err != nil {
        panic(err)
    }

    // Wrap with caching (TTL is configured on the wrapper, not the data source)
    cachedDS := datasource.NewInMemoryCachingDataSource(ds, obs,
        datasource.WithCacheTTL(5 * time.Minute),
    )
    _ = cachedDS
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

Keep the host fixed with the HTTP client's `base_url` and escape every
untrusted value:

```lua
local path = string.format("/users/%s/data", url.path_escape(subject))
local response, err = http.get(path)
```

Do not concatenate token claims or request headers into a URL without
`url.path_escape()`. A `sub` claim like `../admin` or `x?role=admin` would
otherwise change the path or query.

## Best Practices

1. **Validate Config**: Check for required config values at the start of fetch()
2. **Handle Errors Gracefully**: Use error() for fatal errors, return nil for non-fatal
3. **Add Context**: Enrich response data with metadata (source, issuer, etc.)
4. **Use Helper Functions**: Extract common logic into helper functions
5. **Cache Wisely**: Only include fields in fetch_cache_key that affect the result
6. **Log Debug Info**: Use print() to output debug information
7. **Test Thoroughly**: Write tests for your scripts before deployment
8. **Escape URL Input**: Use `url.path_escape()` for any token or request value in a URL path
9. **Bound Responses**: Set `max_response_bytes` near the largest expected response

## Troubleshooting

### Script Won't Load
- Check Lua syntax
- Ensure fetch() function is defined
- Verify fetch_cache_key() function exists for cacheable data sources

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
- Verify fetch_cache_key() returns consistent results
- Ensure fetch_cache_key() includes all relevant fields
- Check TTL is appropriate for your use case

## Additional Resources

- [LUA_DATASOURCE.md](../LUA_DATASOURCE.md) - Full documentation
- [internal/lua/README.md](../../lua/README.md) - Lua services documentation
- Test files in `internal/datasource/lua_datasource_test.go` for more examples
