package lua

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"

	lua "github.com/yuin/gopher-lua"

	"github.com/project-kessel/parsec/internal/httpclient"
)

// RequestOptions is a function that can modify a request before it is sent.
// This can be used to add authentication headers, modify URLs, etc.
type RequestOptions func(*http.Request) error

// httpServiceConfig collects option values during construction.
type httpServiceConfig struct {
	requestOptions RequestOptions
	baseURL        string
}

// HTTPServiceOption configures optional settings for NewHTTPService.
type HTTPServiceOption func(*httpServiceConfig)

// WithRequestOptions sets a function that processes requests before sending.
func WithRequestOptions(ro RequestOptions) HTTPServiceOption {
	return func(c *httpServiceConfig) { c.requestOptions = ro }
}

// WithBaseURL sets an origin-form base (scheme + host, optional trailing slash
// only) that relative Lua URLs resolve against. Empty or omitted preserves
// absolute-URL-only behavior. Path, query, and fragment components are rejected.
func WithBaseURL(base string) HTTPServiceOption {
	return func(c *httpServiceConfig) { c.baseURL = base }
}

// HTTPService provides HTTP client functionality to Lua scripts.
type HTTPService struct {
	ctx            context.Context
	client         *http.Client
	requestOptions RequestOptions
	baseURL        string // empty = absolute Lua URLs only; stored origin string
}

// NewHTTPService creates a new HTTP service. ctx is required and propagated
// to every outgoing request, enabling cancellation, tracing, and request-ID
// propagation. client is the fully-configured HTTP client (auth, timeout,
// transport already set) and must not be nil. Optional settings are provided
// via HTTPServiceOption.
func NewHTTPService(ctx context.Context, client *http.Client, opts ...HTTPServiceOption) (*HTTPService, error) {
	if client == nil {
		return nil, fmt.Errorf("client is required")
	}

	var cfg httpServiceConfig
	for _, opt := range opts {
		opt(&cfg)
	}

	if _, err := httpclient.ParseBaseURL(cfg.baseURL); err != nil {
		return nil, err
	}

	return &HTTPService{
		ctx:            ctx,
		client:         client,
		requestOptions: cfg.requestOptions,
		baseURL:        cfg.baseURL,
	}, nil
}

// resolveRequestURL returns an absolute URL for http.NewRequest. Lua URLs
// with a scheme are used as-is. Relative URLs resolve against baseURL.
func (s *HTTPService) resolveRequestURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid url %q: %w", raw, err)
	}
	if parsed.Scheme != "" {
		return raw, nil
	}
	if parsed.Host != "" {
		return "", fmt.Errorf("relative url %q with host but no scheme is not allowed", raw)
	}
	if s.baseURL == "" {
		return "", fmt.Errorf("relative url %q requires a configured base_url", raw)
	}
	base, err := httpclient.ParseBaseURL(s.baseURL)
	if err != nil {
		return "", err
	}
	return base.ResolveReference(parsed).String(), nil
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
	rawURL := L.CheckString(1)
	headers := s.parseHeaders(L, 2)

	resolved, err := s.resolveRequestURL(rawURL)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	req, err := http.NewRequestWithContext(s.ctx, "GET", resolved, nil)
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
	rawURL := L.CheckString(1)
	body := L.CheckString(2)
	headers := s.parseHeaders(L, 3)

	resolved, err := s.resolveRequestURL(rawURL)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	req, err := http.NewRequestWithContext(s.ctx, "POST", resolved, bytes.NewBufferString(body))
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
	rawURL := L.CheckString(2)

	var body io.Reader
	bodyStr := L.OptString(3, "")
	if bodyStr != "" {
		body = bytes.NewBufferString(bodyStr)
	}

	headers := s.parseHeaders(L, 4)

	resolved, err := s.resolveRequestURL(rawURL)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(err.Error()))
		return 2
	}

	req, err := http.NewRequestWithContext(s.ctx, method, resolved, body)
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
