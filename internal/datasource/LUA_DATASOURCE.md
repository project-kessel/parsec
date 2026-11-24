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
- **URL helpers** - Escape untrusted values before putting them in a URL
- **Base64 and audit** - Encode values and record audit signals

Scripts run in a sandbox. Only the `base`, `table`, `string`, and `math`
standard libraries are loaded. See [Security Model](#security-model).

## Creating a LuaDataSource

### Basic (Non-Cacheable) Data Source

```go
import (
    "net/http"
    "time"
    "github.com/project-kessel/parsec/internal/datasource"
    "github.com/project-kessel/parsec/internal/httpclient"
    "github.com/project-kessel/parsec/internal/lua"
)

script := `
function fetch(input)
  local path = "/user/" .. url.path_escape(input.subject.subject)
  local response = http.get(path)
  
  if response ~= nil and response.status == 200 then
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
    HTTP: httpclient.LuaClient{
        Client:  &http.Client{Timeout: 30 * time.Second},
        BaseURL: "https://api.example.com", // fixes the host; Lua passes paths
    },
    MaxResponseBytes: 64 << 10, // optional; default 1 MiB
    RequestOptions: func(req *http.Request) error {
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
  local path = "/user/" .. url.path_escape(input.subject.subject)
  local response = http.get(path)
  
  if response ~= nil and response.status == 200 then
    return {
      data = response.body,
      content_type = "application/json"
    }
  end
  
  return nil
end

function fetch_cache_key(input)
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
    HTTP: httpclient.LuaClient{
        Client:  &http.Client{Timeout: 30 * time.Second},
        BaseURL: "https://api.example.com",
    },
    RequestOptions: func(req *http.Request) error {
        apiKey, _ := configSource.Get("api_key")
        req.Header.Set("Authorization", "Bearer " + apiKey.(string))
        return nil
    },
})

// Wrap with caching layer
cachedDS := datasource.NewInMemoryCachingDataSource(ds, obs,
    datasource.WithCacheTTL(5 * time.Minute),
)
```

## Configuration

### LuaDataSourceConfig (Basic)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `Name` | `string` | Yes | Unique name for this data source |
| `Script` | `string` | Yes | Lua script with `fetch` function |
| `ConfigSource` | `lua.ConfigSource` | No | Configuration source for the script |
| `HTTP` | `httpclient.LuaClient` | No | HTTP client (timeout, auth, TLS) and optional base URL for relative Lua URLs. Zero value uses `http.DefaultClient` |
| `RequestOptions` | `lua.RequestOptions` | No | Function to modify HTTP requests before sending |
| `MaxResponseBytes` | `int64` | No | Maximum HTTP response body size per request. `0` means 1 MiB; negative is rejected |
| `Observer` | `datasource.LuaObserver` | No | Lua execution events. Defaults to a no-op observer |

### CacheableLuaDataSourceConfig (With Caching)

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `Name` | `string` | Yes | Unique name for this data source |
| `Script` | `string` | Yes | Lua script with `fetch` and cache key functions |
| `ConfigSource` | `lua.ConfigSource` | No | Configuration source for the script |
| `HTTP` | `httpclient.LuaClient` | No | HTTP client (timeout, auth, TLS) and optional base URL for relative Lua URLs. Zero value uses `http.DefaultClient` |
| `RequestOptions` | `lua.RequestOptions` | No | Function to modify HTTP requests before sending |
| `MaxResponseBytes` | `int64` | No | Maximum HTTP response body size per request. `0` means 1 MiB; negative is rejected |
| `Observer` | `datasource.LuaObserver` | No | Lua execution events. Defaults to a no-op observer |

### YAML configuration

```yaml
data_sources:
  - name: user_data
    type: lua
    script_file: ./scripts/user_data.lua
    http:
      timeout: 5s
      base_url: "https://api.example.com"   # fixed host for relative Lua URLs
      http_auth:
        type: bearer
        token: "${USER_API_TOKEN}"
    max_response_bytes: 65536               # optional, default 1048576 (1 MiB)
```

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

### Optional Function: fetch_cache_key

For cacheable data sources, define a `fetch_cache_key` function:

```lua
function fetch_cache_key(input)
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
- Return `nil` to skip the cache for that request (no read, no write)
- Audit signals a script records with `audit.record()` inside `fetch()` are
  not recorded again on a cache hit, because `fetch()` does not run

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

Each call returns `(nil, error)` instead of a response when:
- the URL is invalid, uses a scheme other than `http` or `https`, or is
  relative without a configured `base_url`
- the request fails (connection error, timeout, cancelled context)
- the response body is larger than `max_response_bytes`. The error string
  starts with `response body exceeds max_response_bytes`. The partial body
  is never returned.

### URL Service

```lua
-- Escape an untrusted value for use as ONE path segment.
-- Encodes "/", "?", "#", spaces, and the dot segments "." and "..".
local path = "/users/" .. url.path_escape(input.subject.subject)

-- url.encode is the older helper. It applies Go's url.PathEscape but does
-- not encode "." or "..". Prefer url.path_escape for untrusted input.
local dn = url.encode("/C=US/ST=North Carolina")
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
  -- Relative path: the host comes from the HTTP client's base_url
  local response = http.get("/user/" .. url.path_escape(subject), headers)
  
  if response ~= nil and response.status == 200 then
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
  
  local path = string.format("/user/%s/%s", url.path_escape(region or "default"), url.path_escape(subject))
  local response = http.get(path)
  
  if response ~= nil and response.status == 200 then
    return {
      data = response.body,
      content_type = "application/json"
    }
  end
  
  return nil
end

function fetch_cache_key(input)
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
3. **Caching**: Implement `fetch_cache_key` for data that can be cached
4. **Validation**: Validate input data before making external calls
5. **Logging**: Use print() for debugging (output goes to stdout)
6. **Performance**: Minimize the number of HTTP calls per fetch
7. **Security**: Store sensitive values (API keys) in config, not in scripts.
   Prefer `http_auth` on the HTTP client over building headers in Lua
8. **Fixed hosts**: Set `base_url` on the HTTP client and pass only relative
   paths from Lua. Never build the scheme or host from token or request data
9. **Escape input**: Wrap every token claim, header, or request value placed in
   a URL path with `url.path_escape()`
10. **Size limits**: Set `max_response_bytes` close to the largest expected
    response
11. **Testing**: Test your Lua scripts thoroughly before deployment

## Shipped scripts

[`configs/scripts/export_compliance.lua`](../../configs/scripts/export_compliance.lua)
builds a minimal `x-rh-identity` and GETs the compliance endpoint. Set
`compliance_api` to a path (e.g. `/v1/compliance`) when the named HTTP client
has `base_url`, or to a full URL (contains `://`) for env overlay via
`PARSEC_DATA_SOURCES__N__CONFIG__COMPLIANCE_API`.
Wire it from CEL with `datasource("export_compliance")`, gated on
`request.additional.context_extensions.export_compliance` (opt-out: skip only
when the value is `"false"`; absent key means on). `datasource()` is null when
the source is not registered, so missing config is fail-safe.

## Integration with Caching

Only `CacheableLuaDataSource` implements the `Cacheable` interface and can be wrapped with caching layers:

```go
// Create cacheable data source
cacheableDS, err := datasource.NewCacheableLuaDataSource(datasource.CacheableLuaDataSourceConfig{
    Name:   "user-data",
    Script: script,
})

// Wrap with in-memory caching (TTL is configured on the wrapper)
cachedDS := datasource.NewInMemoryCachingDataSource(cacheableDS, obs,
    datasource.WithCacheTTL(5 * time.Minute),
)

// Or distributed caching
cachedDS := datasource.NewDistributedCachingDataSource(cacheableDS, datasource.DistributedCachingConfig{
    GroupName:      "lua-datasource",
    CacheSizeBytes: 64 << 20,  // 64MB
    CacheTTL:       5 * time.Minute,
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

## Security Model

Lua scripts are supplied through configuration (for example the
`parsec-config` Secret). They run inside the parsec process, which holds
signing keys and upstream credentials. The sandbox limits what a script can
reach if that configuration is modified, and limits what untrusted token and
request data can influence.

### Standard library sandbox

Every Lua state is created with `lua.Options{SkipOpenLibs: true}` through
`luaservices.NewSandboxedState()`. Only these standard libraries are opened:

| Library | Available |
|---------|-----------|
| base (`pairs`, `ipairs`, `pcall`, `error`, `tostring`, `type`, `setmetatable`, `print`, `loadstring`, ...) | Yes |
| `table`, `string`, `math` | Yes |
| `os`, `io`, `debug`, `package`, `coroutine`, `channel` | No |
| `dofile`, `loadfile`, `require`, `module` | No (removed from base) |

Calling `os.execute()`, `io.open()`, `debug.getinfo()`, or `require()`
raises a Lua error. Scripts that used `os.time()` must drop it or receive
the value through `config` or the input table.

The sandbox applies everywhere a script is loaded: `fetch`,
`fetch_cache_key`, the start-up check that `fetch` exists, and Lua trust
validators. The start-up check matters because loading a script runs its
top-level code.

### Outbound HTTP

- **Schemes.** Only `http` and `https` URLs are accepted. Any other scheme,
  such as `file`, `ftp`, or `gopher`, returns `(nil, error)` before a
  request is built.
- **Fixed host with `base_url`.** When the HTTP client has a `base_url`,
  relative Lua paths resolve against it. `base_url` must be origin-form
  (scheme and host only). It must use `https` when `http_auth` or request
  options inject credentials. Protocol-relative URLs such as `//evil.example`
  are rejected, so a path cannot switch hosts.
- **Escaping.** `url.path_escape()` keeps an untrusted value inside one path
  segment, so a `sub` claim like `../admin` or `x?role=admin` cannot change
  the path or add a query.
- **Redirects for credentialed clients.** A client that injects
  credentials, through `http_auth` or request options, only follows
  redirects that keep the same scheme, host, and port. A redirect to another
  host or port, or from `https` to `http`, fails the call with
  `(nil, "request failed: ... redirect to a different origin refused ...")`
  and the target is never contacted. This matters because credential
  transports add their headers on every hop, and Go never strips custom
  headers such as `x-rh-apitoken`. Clients without credentials keep Go's
  default redirect behaviour.
- **Response size.** Bodies are read through `io.LimitReader`, capped by
  `max_response_bytes` (default 1 MiB). A larger body returns
  `(nil, "response body exceeds max_response_bytes ...")`. When the upstream
  sends `Content-Length`, an oversized response is rejected before any of the
  body is read.

### Why there is no per-data-source host allowlist

The security audit (RHCLOUD-50304, FIND-003) proposed an `allowed_hosts`
list. It was reviewed against the current code and not added, for these
reasons:

1. **Same trust boundary.** An `allowed_hosts` list would live in the same
   configuration as the script. Anyone who can change the script can also
   change the list, so it does not constrain the configuration author.
2. **Token data cannot pick the host.** The only untrusted inputs are token
   claims and request attributes. With `base_url` plus relative paths and
   `url.path_escape()`, they can only affect one escaped path segment.
   Protocol-relative and non-http(s) URLs are rejected.
3. **The shipped scripts are safe.** `configs/scripts/export_compliance.lua`
   uses a configured path and sends identity data in a header, not the URL.
   The examples now use `base_url` and `url.path_escape()`.

### Known limitations

- **Unescaped absolute URLs.** A script that concatenates untrusted input into
  an absolute URL without `url.path_escape()` can still be steered. Follow the
  best practices above.
- **Absolute `http://` URLs with credentials.** Credentialed clients must use
  `https` for `base_url`, and redirects cannot downgrade to `http`. An
  absolute `http://` URL written directly in a script is still sent as
  written. Use relative paths with credentialed clients.
- **Trusted upstream behaviour.** The same-origin redirect rule protects
  credentials from redirects, but it cannot protect against a compromised
  upstream that is itself the configured origin.

## Limitations

1. **No File System Access**: `io`, `dofile`, and `loadfile` are not available
2. **No Subprocess Execution**: `os` is not available
3. **Limited Libraries**: Only `base`, `table`, `string`, and `math`, plus the
   parsec services (`http`, `json`, `config`, `url`, `base64`, `audit`)
4. **Timeout Enforcement**: HTTP requests must complete within configured timeout
5. **Response Size**: HTTP bodies larger than `max_response_bytes` are rejected

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

### Response Body Exceeds max_response_bytes

```
response body exceeds max_response_bytes (limit 1048576 bytes, Content-Length 5242880)
```

The upstream returned more data than allowed. Raise `max_response_bytes` on
the data source if the response is expected, or narrow the request.

### attempt to index a non-table object(nil) with key 'execute'

The script uses a standard library the sandbox removes, such as `os` or `io`.
See [Security Model](#security-model).

### Failed to Decode JSON

Ensure the response body is valid JSON before calling `json.decode()`:

```lua
local data, err = json.decode(response.body)
if data == nil then
  print("Invalid JSON: " .. err)
  return nil
end
```
