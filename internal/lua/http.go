package lua

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"strings"

	lua "github.com/yuin/gopher-lua"

	"github.com/project-kessel/parsec/internal/httpclient"
)

// RequestOptions is a function that can modify a request before it is sent.
// This can be used to add authentication headers, modify URLs, etc.
type RequestOptions func(*http.Request) error

// DefaultMaxResponseBytes is the response body cap applied when no explicit
// limit is configured. It bounds the memory a single upstream response can
// consume, so a misbehaving or hostile upstream cannot OOM the process.
const DefaultMaxResponseBytes int64 = 1 << 20 // 1 MiB

// ErrResponseTooLarge is returned to Lua (as the error string) when an upstream
// response body exceeds the configured maximum size.
var ErrResponseTooLarge = errors.New("response body exceeds max_response_bytes")

// httpServiceConfig collects option values during construction.
type httpServiceConfig struct {
	requestOptions   RequestOptions
	baseURL          string
	maxResponseBytes int64
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

// WithMaxResponseBytes caps how many bytes of a response body are read.
// Zero (or omitting the option) uses [DefaultMaxResponseBytes]. Negative
// values are rejected by [NewHTTPService]. A response larger than the cap is
// not returned to Lua; the call returns (nil, error) instead.
func WithMaxResponseBytes(n int64) HTTPServiceOption {
	return func(c *httpServiceConfig) { c.maxResponseBytes = n }
}

// HTTPService provides HTTP client functionality to Lua scripts.
type HTTPService struct {
	ctx              context.Context
	client           *http.Client
	requestOptions   RequestOptions
	baseURL          string // empty = absolute Lua URLs only; stored origin string
	requireHTTPS     bool   // true when transport or RequestOptions inject credentials
	maxResponseBytes int64  // always > 0 after construction
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

	requireHTTPS := cfg.requestOptions != nil || httpclient.UsesCredentialTransport(client)
	if _, err := httpclient.ParseBaseURL(cfg.baseURL, requireHTTPS); err != nil {
		return nil, err
	}

	if requireHTTPS {
		client = withSameOriginRedirects(client)
	}

	maxResponseBytes, err := ResolveMaxResponseBytes(cfg.maxResponseBytes)
	if err != nil {
		return nil, err
	}

	return &HTTPService{
		ctx:              ctx,
		client:           client,
		requestOptions:   cfg.requestOptions,
		baseURL:          cfg.baseURL,
		requireHTTPS:     requireHTTPS,
		maxResponseBytes: maxResponseBytes,
	}, nil
}

// withSameOriginRedirects returns a shallow copy of client whose redirect
// policy refuses cross-origin redirects, keeping any existing CheckRedirect.
// It is applied whenever credentials are in play: a credential-injecting
// transport, or RequestOptions, whose headers net/http copies to every redirect
// hop (custom headers are never stripped). The caller's client is not modified.
func withSameOriginRedirects(client *http.Client) *http.Client {
	c := *client
	c.CheckRedirect = httpclient.WithSameOriginRedirects(client.CheckRedirect)
	return &c
}

// ResolveMaxResponseBytes applies the default to a configured response size
// limit. Zero means [DefaultMaxResponseBytes]; negative values are an error.
func ResolveMaxResponseBytes(n int64) (int64, error) {
	switch {
	case n < 0:
		return 0, fmt.Errorf("max_response_bytes must not be negative, got %d", n)
	case n == 0:
		return DefaultMaxResponseBytes, nil
	default:
		return n, nil
	}
}

// resolveRequestURL returns an absolute URL for http.NewRequest. Lua URLs
// with a scheme are used as-is. Relative URLs resolve against baseURL.
func (s *HTTPService) resolveRequestURL(raw string) (string, error) {
	parsed, err := url.Parse(raw)
	if err != nil {
		return "", fmt.Errorf("invalid url %q: %w", raw, err)
	}
	if parsed.Scheme != "" {
		switch strings.ToLower(parsed.Scheme) {
		case "http", "https":
			return raw, nil
		default:
			return "", fmt.Errorf("url %q: scheme %q is not allowed (must be http or https)", raw, parsed.Scheme)
		}
	}
	if parsed.Host != "" {
		return "", fmt.Errorf("relative url %q with host but no scheme is not allowed", raw)
	}
	if s.baseURL == "" {
		return "", fmt.Errorf("relative url %q requires a configured base_url", raw)
	}
	base, err := httpclient.ParseBaseURL(s.baseURL, s.requireHTTPS)
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
	return s.do(L, http.MethodGet, rawURL, nil, headers)
}

// luaHTTPPost implements HTTP POST
// Args: url (string), body (string), [headers (table)]
// Returns: response table {status=int, body=string, headers=table} or (nil, error)
func (s *HTTPService) luaHTTPPost(L *lua.LState) int {
	rawURL := L.CheckString(1)
	body := L.CheckString(2)
	headers := s.parseHeaders(L, 3)
	return s.do(L, http.MethodPost, rawURL, bytes.NewBufferString(body), headers)
}

// luaHTTPRequest implements a generic HTTP request
// Args: method (string), url (string), [body (string)], [headers (table)]
// Returns: response table {status=int, body=string, headers=table} or (nil, error)
func (s *HTTPService) luaHTTPRequest(L *lua.LState) int {
	method := L.CheckString(1)
	rawURL := L.CheckString(2)

	var body io.Reader
	if bodyStr := L.OptString(3, ""); bodyStr != "" {
		body = bytes.NewBufferString(bodyStr)
	}

	headers := s.parseHeaders(L, 4)
	return s.do(L, method, rawURL, body, headers)
}

// do resolves the URL, builds and sends the request, and pushes either the
// response table or (nil, error) onto the Lua stack. All Lua HTTP entry points
// go through here so URL validation and the response size limit apply equally.
func (s *HTTPService) do(L *lua.LState, method, rawURL string, body io.Reader, headers map[string]string) int {
	resolved, err := s.resolveRequestURL(rawURL)
	if err != nil {
		return pushError(L, err.Error())
	}

	req, err := http.NewRequestWithContext(s.ctx, method, resolved, body)
	if err != nil {
		return pushError(L, fmt.Sprintf("failed to create request: %v", err))
	}

	for key, value := range headers {
		req.Header.Set(key, value)
	}

	if s.requestOptions != nil {
		if err := s.requestOptions(req); err != nil {
			return pushError(L, fmt.Sprintf("request options failed: %v", err))
		}
	}

	resp, err := s.client.Do(req)
	if err != nil {
		return pushError(L, fmt.Sprintf("request failed: %v", err))
	}
	defer func() { _ = resp.Body.Close() }()

	tbl, err := s.responseToLua(L, resp)
	if err != nil {
		return pushError(L, err.Error())
	}
	L.Push(tbl)
	return 1
}

// pushError pushes the Lua (nil, message) error convention and returns 2.
func pushError(L *lua.LState, msg string) int {
	L.Push(lua.LNil)
	L.Push(lua.LString(msg))
	return 2
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

// responseToLua converts an HTTP response to a Lua table. It returns an error
// wrapping [ErrResponseTooLarge] when the body exceeds maxResponseBytes, so a
// script never sees a silently truncated body.
func (s *HTTPService) responseToLua(L *lua.LState, resp *http.Response) (*lua.LTable, error) {
	if resp.ContentLength > s.maxResponseBytes {
		return nil, fmt.Errorf("%w (limit %d bytes, Content-Length %d)",
			ErrResponseTooLarge, s.maxResponseBytes, resp.ContentLength)
	}

	tbl := L.NewTable()

	// Status code
	L.SetField(tbl, "status", lua.LNumber(resp.StatusCode))

	// Body: read at most one byte past the limit to detect oversized bodies
	// whose length was not advertised up front (e.g. chunked encoding).
	readLimit := s.maxResponseBytes
	if readLimit < math.MaxInt64 {
		readLimit++
	}
	bodyBytes, err := io.ReadAll(io.LimitReader(resp.Body, readLimit))
	switch {
	case err != nil:
		L.SetField(tbl, "body", lua.LString(""))
		L.SetField(tbl, "error", lua.LString(fmt.Sprintf("failed to read body: %v", err)))
	case int64(len(bodyBytes)) > s.maxResponseBytes:
		return nil, fmt.Errorf("%w (limit %d bytes)", ErrResponseTooLarge, s.maxResponseBytes)
	default:
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

	return tbl, nil
}
