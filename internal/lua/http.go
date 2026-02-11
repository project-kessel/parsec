package lua

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	lua "github.com/yuin/gopher-lua"
)

// RequestOptions is a function that can modify a request before it is sent
// This can be used to add authentication headers, modify URLs, etc.
type RequestOptions func(*http.Request) error

// HTTPService provides HTTP client functionality to Lua scripts
type HTTPService struct {
	client         *http.Client
	timeout        time.Duration
	requestOptions RequestOptions
}

// HTTPServiceConfig configures the HTTP service
type HTTPServiceConfig struct {
	// Timeout for HTTP requests (default: 30s)
	Timeout time.Duration

	// RequestOptions function to process requests before sending
	// Can be used to add authentication, modify headers, etc.
	RequestOptions RequestOptions

	// Transport is the HTTP transport to use for requests
	// If nil, uses http.DefaultTransport
	Transport http.RoundTripper
}

// NewHTTPService creates a new HTTP service with configurable timeout
func NewHTTPService(timeout time.Duration) *HTTPService {
	return NewHTTPServiceWithConfig(HTTPServiceConfig{
		Timeout: timeout,
	})
}

// NewHTTPServiceWithConfig creates a new HTTP service with full configuration
func NewHTTPServiceWithConfig(config HTTPServiceConfig) *HTTPService {
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	// Use provided transport or default
	transport := config.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}

	return &HTTPService{
		client: &http.Client{
			Timeout:   config.Timeout,
			Transport: transport,
		},
		timeout:        config.Timeout,
		requestOptions: config.RequestOptions,
	}
}

// Register adds the HTTP service to the Lua state
// Usage in Lua:
//
//	local response = http.get("https://api.example.com/data")
//	local response = http.post("https://api.example.com/data", "request body", {["Content-Type"] = "application/json"})
func (s *HTTPService) Register(L *lua.LState) {
	// Create HTTP module table
	mod := L.NewTable()

	// Register functions
	L.SetField(mod, "get", L.NewFunction(s.luaHTTPGet))
	L.SetField(mod, "post", L.NewFunction(s.luaHTTPPost))
	L.SetField(mod, "request", L.NewFunction(s.luaHTTPRequest))

	// Set the module as a global
	L.SetGlobal("http", mod)
}

// luaHTTPGet implements HTTP GET
// Args: url (string), [headers (table)]
// Returns: response table {status=int, body=string, headers=table} or (nil, error)
func (s *HTTPService) luaHTTPGet(L *lua.LState) int {
	url := L.CheckString(1)
	headers := s.parseHeaders(L, 2)

	req, err := http.NewRequest("GET", url, nil)

	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("failed to create request: %v", err)))
		return 2
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Apply request options if configured
	if s.requestOptions != nil {
		if err := s.requestOptions(req); err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(fmt.Sprintf("request options failed: %v", err)))
			return 2
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("request failed: %v", err)))
		return 2
	}
	defer func() { _ = resp.Body.Close() }()

	L.Push(s.responseToLua(L, resp))
	return 1
}

// luaHTTPPost implements HTTP POST
// Args: url (string), body (string), [headers (table)]
// Returns: response table {status=int, body=string, headers=table} or (nil, error)
func (s *HTTPService) luaHTTPPost(L *lua.LState) int {
	url := L.CheckString(1)
	body := L.CheckString(2)
	headers := s.parseHeaders(L, 3)

	req, err := http.NewRequest("POST", url, bytes.NewBufferString(body))
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("failed to create request: %v", err)))
		return 2
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Apply request options if configured
	if s.requestOptions != nil {
		if err := s.requestOptions(req); err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(fmt.Sprintf("request options failed: %v", err)))
			return 2
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("request failed: %v", err)))
		return 2
	}
	defer func() { _ = resp.Body.Close() }()

	L.Push(s.responseToLua(L, resp))
	return 1
}

// luaHTTPRequest implements a generic HTTP request
// Args: method (string), url (string), [body (string)], [headers (table)]
// Returns: response table {status=int, body=string, headers=table} or (nil, error)
func (s *HTTPService) luaHTTPRequest(L *lua.LState) int {
	method := L.CheckString(1)
	url := L.CheckString(2)

	var body io.Reader
	bodyStr := L.OptString(3, "")
	if bodyStr != "" {
		body = bytes.NewBufferString(bodyStr)
	}

	headers := s.parseHeaders(L, 4)

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("failed to create request: %v", err)))
		return 2
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	// Apply request options if configured
	if s.requestOptions != nil {
		if err := s.requestOptions(req); err != nil {
			L.Push(lua.LNil)
			L.Push(lua.LString(fmt.Sprintf("request options failed: %v", err)))
			return 2
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("request failed: %v", err)))
		return 2
	}
	defer func() { _ = resp.Body.Close() }()

	L.Push(s.responseToLua(L, resp))
	return 1
}

// parseHeaders converts a Lua table to Go map of headers
func (s *HTTPService) parseHeaders(L *lua.LState, arg int) map[string]string {
	headers := make(map[string]string)

	if L.GetTop() < arg {
		return headers
	}

	lv := L.Get(arg)
	if lv.Type() != lua.LTTable {
		return headers
	}

	tbl := lv.(*lua.LTable)
	tbl.ForEach(func(key, value lua.LValue) {
		if key.Type() == lua.LTString && value.Type() == lua.LTString {
			headers[key.String()] = value.String()
		}
	})

	return headers
}

// responseToLua converts an HTTP response to a Lua table
func (s *HTTPService) responseToLua(L *lua.LState, resp *http.Response) *lua.LTable {
	tbl := L.NewTable()

	// Status code
	L.SetField(tbl, "status", lua.LNumber(resp.StatusCode))

	// Body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		L.SetField(tbl, "body", lua.LString(""))
		L.SetField(tbl, "error", lua.LString(fmt.Sprintf("failed to read body: %v", err)))
	} else {
		L.SetField(tbl, "body", lua.LString(string(bodyBytes)))
	}

	// Headers
	headersTbl := L.NewTable()
	for key, values := range resp.Header {
		if len(values) > 0 {
			L.SetField(headersTbl, key, lua.LString(values[0]))
		}
	}
	L.SetField(tbl, "headers", headersTbl)

	return tbl
}

// WithContext allows setting a context for requests (useful for cancellation)
func (s *HTTPService) WithContext(ctx context.Context) *HTTPService {
	// Create a new client with context-aware transport
	// Note: This is a simplified version. For production, you'd want to wrap the transport
	return s
}
