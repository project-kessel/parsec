# Lua Services Package

This package provides Lua services for use with the LuaDataSource. These services expose Go functionality to Lua scripts in a safe and controlled manner.

## Sandboxed Lua States

Always create Lua states that run configuration-supplied scripts with
`NewSandboxedState()`, never `lua.NewState()`. It uses
`lua.Options{SkipOpenLibs: true}` and opens only `base`, `table`, `string`,
and `math`. It also removes `dofile`, `loadfile`, `require`, `module`, and
`_printregs` from the base library. `os`, `io`, `debug`, `package`,
`coroutine`, and `channel` are not available.

`ValidateFunction` uses a sandboxed state too, because loading a script runs
its top-level code.

## Available Services

### HTTP Service

The HTTP service provides HTTP client functionality to Lua scripts.

#### Functions

- `http.get(url, [headers])` - Make a GET request
  - Returns: `{status=int, body=string, headers=table}` or `(nil, error)`
  
- `http.post(url, body, [headers])` - Make a POST request
  - Returns: `{status=int, body=string, headers=table}` or `(nil, error)`
  
- `http.request(method, url, [body], [headers])` - Make a generic HTTP request
  - Returns: `{status=int, body=string, headers=table}` or `(nil, error)`

URLs may be absolute (`https://host/path`) or relative (`/v1/compliance`).
Relative URLs resolve against the HTTP client's optional `base_url`
(`WithBaseURL`). `base_url` must be origin-form (scheme + host, optional
trailing `/` only); path prefixes are rejected at startup. Use Lua paths that
start with `/` so the joined URL is `{base}/path`. If the Lua URL has a scheme,
it is used as-is even when `base_url` is set. A relative URL with no `base_url`
returns `(nil, error)` and does not hit the network.

Only `http` and `https` schemes are accepted. Any other scheme returns
`(nil, error)` without sending a request.

Response bodies are capped by `WithMaxResponseBytes` (default
`DefaultMaxResponseBytes`, 1 MiB). A larger body returns
`(nil, "response body exceeds max_response_bytes ...")`, never a truncated
body. If the upstream sends `Content-Length`, the check happens before any of
the body is read.

#### Example

```lua
-- Simple GET request
local response = http.get("https://api.example.com/data")
if response.status == 200 then
  print("Success: " .. response.body)
end

-- GET with headers
local headers = {["Authorization"] = "Bearer token123"}
local response = http.get("https://api.example.com/protected", headers)

-- POST with JSON body
local body = json.encode({key = "value"})
local headers = {["Content-Type"] = "application/json"}
local response = http.post("https://api.example.com/create", body, headers)

-- Generic request
local response = http.request("PUT", "https://api.example.com/update", body, headers)
```

### URL Service

The URL service escapes values for use in URLs.

#### Functions

- `url.path_escape(string)` - Escape a value for use as a single URL path segment
  - Encodes `/`, `?`, `#`, spaces and other reserved characters, plus the dot
    segments `.` and `..`. Use this for any token or request value placed in a path.
  - Returns: `escaped_string`

- `url.encode(string)` - Apply Go's `url.PathEscape`
  - Does not encode `.` or `..`. Kept for compatibility; prefer `url.path_escape`
    for untrusted input.
  - Returns: `escaped_string`

#### Example

```lua
-- base_url on the HTTP client fixes the host; the subject stays in one segment
local response = http.get("/users/" .. url.path_escape(input.subject.subject))
```

### JSON Service

The JSON service provides JSON encoding and decoding functionality.

#### Functions

- `json.encode(value)` - Encode a Lua value to JSON string
  - Returns: `json_string` or `(nil, error)`
  
- `json.decode(json_string)` - Decode a JSON string to a Lua value
  - Returns: `value` or `(nil, error)`

#### Example

```lua
-- Encode to JSON
local obj = {
  name = "Alice",
  age = 30,
  roles = {"admin", "user"}
}
local jsonStr = json.encode(obj)
-- Result: '{"name":"Alice","age":30,"roles":["admin","user"]}'

-- Decode from JSON
local data = json.decode('{"key":"value","num":42}')
print(data.key)  -- "value"
print(data.num)  -- 42

-- Round-trip
local original = {test = "data"}
local encoded = json.encode(original)
local decoded = json.decode(encoded)
```

### Base64 Service

The base64 service provides standard base64 encoding and decoding.

#### Functions

- `base64.encode(string)` - Encode a string with standard base64
  - Returns: `encoded_string`

- `base64.decode(string)` - Decode a standard base64 string
  - Returns: `decoded_string` or `(nil, error)`

#### Example

```lua
local encoded = base64.encode(json.encode({identity = {org_id = "org-1"}}))
local headers = {["x-rh-identity"] = encoded}
local response = http.get("https://export-compliance.example.internal/v1/compliance", headers)
```

### Config Service

The Config service provides access to configuration values passed to the LuaDataSource.

#### Functions

- `config.get(key, [default])` - Get a configuration value
  - Returns: value or default if not found
  
- `config.has(key)` - Check if a configuration key exists
  - Returns: `bool`
  
- `config.keys()` - Get all configuration keys
  - Returns: `table` (array of strings)

#### Example

```lua
-- Get config values
local apiKey = config.get("api_key")
local timeout = config.get("timeout", 30)  -- with default

-- Check if key exists
if config.has("feature_flag") then
  -- use the feature
end

-- List all keys
local keys = config.keys()
for i, key in ipairs(keys) do
  print(key .. " = " .. tostring(config.get(key)))
end
```

## Type Conversions

### Go to Lua

- `string` → `lua.LString`
- `int`, `int64`, `float64` → `lua.LNumber`
- `bool` → `lua.LBool`
- `map[string]interface{}` → Lua table (object)
- `[]interface{}` → Lua table (array)
- `nil` → `lua.LNil`

### Lua to Go

- `lua.LString` → `string`
- `lua.LNumber` → `float64`
- `lua.LBool` → `bool`
- Lua table (with integer keys 1..N) → `[]interface{}`
- Lua table (with string keys) → `map[string]interface{}`
- `lua.LNil` → `nil`

## Thread Safety

Each service instance can be registered to multiple Lua states. However, Lua states themselves are not thread-safe. The LuaDataSource creates a new Lua state for each request, ensuring thread safety.

## Configuration

### HTTP Service

```go
// Simple usage with a pre-configured HTTP client (must not be nil)
client := &http.Client{Timeout: 30 * time.Second}
httpService, err := lua.NewHTTPService(ctx, client)

// Relative Lua URLs resolve against base_url (optional)
httpService, err := lua.NewHTTPService(ctx, client,
    lua.WithBaseURL("https://entitlements.internal.example.com"),
)

// Cap response bodies (optional; default DefaultMaxResponseBytes = 1 MiB)
httpService, err := lua.NewHTTPService(ctx, client,
    lua.WithMaxResponseBytes(64 << 10),
)

// With request options (per-request hooks applied before sending)
httpService, err := lua.NewHTTPService(ctx, client,
    lua.WithRequestOptions(func(req *http.Request) error {
        req.Header.Set("X-Tenant-ID", tenantFromContext(ctx))
        return nil
    }),
)
```

#### Request Options

The `RequestOptions` function allows you to modify HTTP requests before they are sent. This is useful for:
- Adding authentication headers
- Modifying URLs (e.g., adding query parameters)
- Setting custom headers
- Implementing request signing

**Example: Adding Authentication**
```go
requestOptions := func(req *http.Request) error {
    req.Header.Set("Authorization", "Bearer secret-token")
    return nil
}
```

**Example: Adding Query Parameters**
```go
requestOptions := func(req *http.Request) error {
    q := req.URL.Query()
    q.Add("api_key", "secret")
    q.Add("tenant", "acme-corp")
    req.URL.RawQuery = q.Encode()
    return nil
}
```

### Config Service

The Config Service uses a `ConfigSource` interface to retrieve configuration values:

```go
// Simple in-memory configuration
configSource := lua.NewMapConfigSource(map[string]interface{}{
    "api_key": "secret",
    "timeout": 60,
    "enabled": true,
})
configService := lua.NewConfigService(configSource)
```

#### Custom Config Sources

You can implement your own `ConfigSource` to back configuration with environment variables, files, remote services, etc:

```go
type ConfigSource interface {
    // Get retrieves a configuration value by key
    // Returns the value and true if found, or nil and false if not found
    Get(key string) (interface{}, bool)
    
    // Keys returns all available configuration keys
    Keys() []string
}
```

**Example: Environment Variable Config Source**
```go
type EnvConfigSource struct{}

func (e *EnvConfigSource) Get(key string) (interface{}, bool) {
    val, ok := os.LookupEnv(key)
    return val, ok
}

func (e *EnvConfigSource) Keys() []string {
    // Return all env var names
    return []string{} // implementation depends on needs
}

configService := lua.NewConfigService(&EnvConfigSource{})
```

### JSON Service

```go
jsonService := lua.NewJSONService()  // no configuration needed
```

## Error Handling

Services follow Lua's convention of returning `(result, error)` tuples:

```lua
local result, err = http.get("https://example.com")
if result == nil then
  print("Error: " .. err)
else
  print("Success: " .. result.body)
end
```

## Security Considerations

1. **Standard Library Sandbox**: `NewSandboxedState()` loads only `base`, `table`, `string`, and `math`. There is no `os`, `io`, `debug`, or module loading
2. **HTTP Timeout**: The HTTP service has a configurable timeout to prevent long-running requests
3. **Response Size Limit**: Bodies are read through `io.LimitReader` and rejected above `max_response_bytes`
4. **Scheme Restriction**: Only `http` and `https` URLs are sent
5. **Fixed Hosts**: With `base_url` and relative paths, script input cannot change the host. Escape untrusted path values with `url.path_escape()`
6. **Isolated State**: Each Lua script runs in its own isolated state

See [LUA_DATASOURCE.md](../datasource/LUA_DATASOURCE.md#security-model) for
the full security model, including why there is no per-data-source host
allowlist.

## Best Practices

1. **Handle Errors**: Always check for errors when calling service functions
2. **Use Timeouts**: Configure appropriate HTTP timeouts for your use case
3. **Validate Inputs**: Validate data before encoding to JSON or making HTTP requests
4. **Cache Config**: Store frequently accessed config values in local variables
5. **Clean JSON**: Use json.encode/decode for reliable serialization

## Example: Complete LuaDataSource Script

```lua
function fetch(input)
  -- Get configuration
  local apiEndpoint = config.get("api_endpoint")
  local apiKey = config.get("api_key")
  
  -- Access input data
  local subject = input.subject.subject
  
  -- Make HTTP request
  local headers = {
    ["Authorization"] = "Bearer " .. apiKey,
    ["Content-Type"] = "application/json"
  }
  
  -- Escape the untrusted subject so it stays in one path segment
  local response = http.get(apiEndpoint .. "/user/" .. url.path_escape(subject), headers)
  
  if response == nil or response.status ~= 200 then
    return nil  -- Data source has nothing to contribute
  end
  
  -- Parse and enhance response
  local userData = json.decode(response.body)
  userData.source = "lua-datasource"
  
  -- Return result
  return {
    data = json.encode(userData),
    content_type = "application/json"
  }
end

function fetch_cache_key(input)
  -- Only cache based on subject
  return {
    subject = {
      subject = input.subject.subject
    }
  }
end
```

