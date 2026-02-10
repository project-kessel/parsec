# LuaDataSource

The LuaDataSource allows you to implement custom data sources using Lua scripts. This provides flexibility to fetch and transform data from various sources without recompiling the application.

There are two variants:
- **`LuaDataSource`** - Basic data source without caching
- **`CacheableLuaDataSource`** - Data source with caching support (implements `Cacheable` interface)

## Overview

A LuaDataSource executes a Lua script that has access to:
- **HTTP client** - Make HTTP requests to external APIs
- **JSON encoder/decoder** - Parse and generate JSON
- **Configuration** - Access configuration values

## Creating a LuaDataSource

### Basic (Non-Cacheable) Data Source

```go
import (
    "net/http"
    "time"
    "github.com/project-kessel/parsec/internal/datasource"
    "github.com/project-kessel/parsec/internal/lua"
)

script := `
function fetch(input)
  local subject = input.subject.subject
  local response = http.get("https://api.example.com/user/" .. subject)
  
  if response.status == 200 then
    return {
      data = response.body,
      content_type = "application/json"
    }
  end
  
  return nil
end
`

// Create config source
configSource := lua.NewMapConfigSource(map[string]interface{}{
    "api_key": "secret123",
})

ds, err := datasource.NewLuaDataSource(datasource.LuaDataSourceConfig{
    Name:         "user-data",
    Script:       script,
    ConfigSource: configSource,
    HTTPTimeout:  30 * time.Second,
    HTTPRequestOptions: func(req *http.Request) error {
        // Automatically add API key to all requests
        apiKey, _ := configSource.Get("api_key")
        req.Header.Set("Authorization", "Bearer " + apiKey.(string))
        return nil
    },
})
```

### Cacheable Data Source

```go
script := `
function fetch(input)
  local subject = input.subject.subject
  local response = http.get("https://api.example.com/user/" .. subject)
  
  if response.status == 200 then
    return {
      data = response.body,
      content_type = "application/json"
    }
  end
  
  return nil
end

function cache_key(input)
  -- Only cache based on subject
  return {
    subject = {
      subject = input.subject.subject
    }
  }
end
`

configSource := lua.NewMapConfigSource(map[string]interface{}{
    "api_key": "secret123",
})

// Use CacheableLuaDataSource for caching support
ds, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
    Name:         "user-data",
    Script:       script,
    ConfigSource: configSource,
    HTTPTimeout:  30 * time.Second,
    HTTPRequestOptions: func(req *http.Request) error {
        apiKey, _ := configSource.Get("api_key")
        req.Header.Set("Authorization", "Bearer " + apiKey.(string))
        return nil
    },
    CacheKeyFunc: "cache_key",  // REQUIRED for cacheable data source
    CacheTTL:     5 * time.Minute,
})

// Wrap with caching layer
cachedDS := datasource.NewInMemoryCachingDataSource(ds)
```

## Configuration

### LuaDataSourceConfig (Basic)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `Name` | `string` | Yes | Unique name for this data source |
| `Script` | `string` | Yes | Lua script with `fetch` function |
| `ConfigSource` | `lua.ConfigSource` | No | Configuration source for the script |
| `HTTPTimeout` | `time.Duration` | No | HTTP request timeout (default: 30s) |
| `HTTPRequestOptions` | `lua.RequestOptions` | No | Function to modify HTTP requests |

### CacheableLuaDataSourceConfig (With Caching)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `Name` | `string` | Yes | Unique name for this data source |
| `Script` | `string` | Yes | Lua script with `fetch` and cache key functions |
| `ConfigSource` | `lua.ConfigSource` | No | Configuration source for the script |
| `HTTPTimeout` | `time.Duration` | No | HTTP request timeout (default: 30s) |
| `HTTPRequestOptions` | `lua.RequestOptions` | No | Function to modify HTTP requests |
| `CacheKeyFunc` | `string` | **Yes** | Name of Lua function for cache key generation |
| `CacheTTL` | `time.Duration` | No | Cache TTL (default: 5m) |

## Script Requirements

### Required Function: fetch

Every script must define a `fetch` function:

```lua
function fetch(input)
  -- Your logic here
  return {
    data = "...",  -- string containing the data
    content_type = "application/json"  -- content type
  }
end
```

**Input Structure:**
```lua
input = {
  subject = {
    subject = "user@example.com",
    issuer = "https://idp.example.com",
    claims = {
      -- Additional claims
    }
  },
  workload = {
    subject = "workload-id",
    issuer = "https://workload-issuer.com",
    claims = {
      -- Workload claims
    }
  },
  request_attributes = {
    method = "POST",
    path = "/api/resource",
    ip_address = "192.168.1.1",
    user_agent = "Mozilla/5.0...",
    headers = {
      ["X-Custom"] = "value"
    },
    additional = {
      -- Additional context
    }
  }
}
```

**Return Value:**
- Return a table with `data` (string) and `content_type` (string) fields
- Return `nil` if the data source has nothing to contribute
- Throw an error for fatal errors that should fail token issuance

### Optional Function: cache_key

For cacheable data sources, you can define a `cache_key` function:

```lua
function cache_key(input)
  -- Return modified input with only relevant fields
  return {
    subject = {
      subject = input.subject.subject
    }
  }
end
```

This function:
- Takes the same input as `fetch`
- Returns a modified input with only fields that affect the result
- Determines what gets cached and the cache key
- Must include all data needed for `fetch` to work

## Available Services

### HTTP Service

```lua
-- GET request
local response = http.get("https://api.example.com/data")

-- GET with headers
local headers = {["Authorization"] = "Bearer token"}
local response = http.get("https://api.example.com/data", headers)

-- POST request
local body = json.encode({key = "value"})
local headers = {["Content-Type"] = "application/json"}
local response = http.post("https://api.example.com/create", body, headers)

-- Generic request
local response = http.request("PUT", "https://api.example.com/update", body, headers)

-- Response structure
response = {
  status = 200,
  body = "...",
  headers = {
    ["Content-Type"] = "application/json"
  }
}
```

### JSON Service

```lua
-- Encode to JSON
local jsonStr = json.encode({key = "value", num = 42})

-- Decode from JSON
local obj = json.decode('{"key":"value","num":42}')
print(obj.key)  -- "value"
print(obj.num)  -- 42
```

### Config Service

```lua
-- Get config value
local apiKey = config.get("api_key")

-- Get with default
local timeout = config.get("timeout", 30)

-- Check if key exists
if config.has("feature_flag") then
  -- use it
end

-- List all keys
local keys = config.keys()
```

## Examples

### Simple API Call

```lua
function fetch(input)
  local subject = input.subject.subject
  local apiKey = config.get("api_key")
  
  local headers = {["Authorization"] = "Bearer " .. apiKey}
  local response = http.get("https://api.example.com/user/" .. subject, headers)
  
  if response.status == 200 then
    return {
      data = response.body,
      content_type = "application/json"
    }
  end
  
  return nil
end
```

### Data Transformation

```lua
function fetch(input)
  local response = http.get("https://api.example.com/data")
  
  if response.status == 200 then
    local data = json.decode(response.body)
    
    -- Transform data
    data.fetched_at = os.time()
    data.source = "lua-datasource"
    data.subject = input.subject.subject
    
    return {
      data = json.encode(data),
      content_type = "application/json"
    }
  end
  
  return nil
end
```

### Conditional Logic

```lua
function fetch(input)
  local userType = input.subject.claims.user_type
  
  if userType == "admin" then
    return fetch_admin_data(input)
  elseif userType == "user" then
    return fetch_user_data(input)
  else
    return nil
  end
end

function fetch_admin_data(input)
  local response = http.get("https://api.example.com/admin/data")
  if response.status == 200 then
    return {data = response.body, content_type = "application/json"}
  end
  return nil
end

function fetch_user_data(input)
  local response = http.get("https://api.example.com/user/data")
  if response.status == 200 then
    return {data = response.body, content_type = "application/json"}
  end
  return nil
end
```

### With Caching

```lua
function fetch(input)
  local subject = input.subject.subject
  local region = input.request_attributes.headers["X-Region"]
  
  local url = string.format("https://api.example.com/user/%s?region=%s", subject, region)
  local response = http.get(url)
  
  if response.status == 200 then
    return {
      data = response.body,
      content_type = "application/json"
    }
  end
  
  return nil
end

function cache_key(input)
  -- Cache based on subject and region
  return {
    subject = {
      subject = input.subject.subject
    },
    request_attributes = {
      headers = {
        ["X-Region"] = input.request_attributes.headers["X-Region"]
      }
    }
  }
end
```

### Error Handling

```lua
function fetch(input)
  local response, err = http.get("https://api.example.com/data")
  
  if response == nil then
    error("Failed to fetch data: " .. err)
  end
  
  if response.status ~= 200 then
    -- Non-200 status is not fatal, just return nil
    return nil
  end
  
  local data, err = json.decode(response.body)
  if data == nil then
    error("Failed to decode JSON: " .. err)
  end
  
  return {
    data = json.encode(data),
    content_type = "application/json"
  }
end
```

## Best Practices

1. **Error Handling**: Use `error()` for fatal errors, return `nil` for non-fatal cases
2. **Timeouts**: Configure appropriate HTTP timeouts for your APIs
3. **Caching**: Implement `cache_key` for data that can be cached
4. **Validation**: Validate input data before making external calls
5. **Logging**: Use print() for debugging (output goes to stdout)
6. **Performance**: Minimize the number of HTTP calls per fetch
7. **Security**: Store sensitive values (API keys) in config, not in scripts
8. **Testing**: Test your Lua scripts thoroughly before deployment

## Integration with Caching

Only `CacheableLuaDataSource` implements the `Cacheable` interface and can be wrapped with caching layers:

```go
// Create cacheable data source
cacheableDS, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
    Name:         "user-data",
    Script:       script,
    CacheKeyFunc: "cache_key",  // Required
    CacheTTL:     5 * time.Minute,
})

// Wrap with in-memory caching
cachedDS := datasource.NewInMemoryCachingDataSource(cacheableDS)

// Or distributed caching
cachedDS := datasource.NewDistributedCachingDataSource(cacheableDS, datasource.DistributedCachingConfig{
    GroupName:      "lua-datasource",
    CacheSizeBytes: 64 << 20,  // 64MB
})
```

**Note:** If you try to wrap a basic `LuaDataSource` (without caching), it will be returned as-is since it doesn't implement the `Cacheable` interface.

## Thread Safety

Each call to `Fetch()` creates a new Lua state, making the LuaDataSource fully thread-safe. Multiple goroutines can safely call `Fetch()` concurrently.

## Performance Considerations

1. **Lua State Creation**: Creating a new Lua state per request has overhead (~1ms)
2. **HTTP Calls**: The main performance factor is external HTTP calls
3. **JSON Encoding**: JSON operations are relatively fast
4. **Script Complexity**: Keep scripts simple; complex logic may impact performance
5. **Caching**: Use caching for data that doesn't change frequently

## Limitations

1. **No File System Access**: Scripts cannot read/write files
2. **No Subprocess Execution**: Scripts cannot execute system commands
3. **Limited Libraries**: Only provided services are available (no standard Lua libraries beyond basics)
4. **Timeout Enforcement**: HTTP requests must complete within configured timeout
5. **Memory Limits**: Lua states have inherent memory limits

## Troubleshooting

### Script Execution Failed

```
script execution failed: [string "..."]:X: <error message>
```

Check your Lua syntax and ensure all referenced functions/variables exist.

### Must Define a 'fetch' Function

The script must include a `fetch` function. Check spelling and syntax.

### Request Failed

HTTP requests can fail due to network issues, timeouts, or invalid URLs. Handle errors appropriately:

```lua
local response, err = http.get(url)
if response == nil then
  error("Request failed: " .. err)
end
```

### Failed to Decode JSON

Ensure the response body is valid JSON before calling `json.decode()`:

```lua
local data, err = json.decode(response.body)
if data == nil then
  print("Invalid JSON: " .. err)
  return nil
end
```

