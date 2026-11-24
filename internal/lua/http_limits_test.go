package lua

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

// runLuaHTTP registers svc in a fresh sandboxed state, runs script, and
// returns the string assigned to the global "result".
func runLuaHTTP(t *testing.T, svc *HTTPService, script string) string {
	t.Helper()
	L := NewSandboxedState()
	defer L.Close()
	svc.Register(L)
	if err := L.DoString(script); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}
	return L.GetGlobal("result").String()
}

// resultScript calls expr and records either "ok:<len>" or "err:<message>".
func resultScript(expr string) string {
	return `
		local resp, err = ` + expr + `
		if resp == nil then
			result = "err:" .. err
		else
			result = "ok:" .. #resp.body
		end
	`
}

func TestResolveMaxResponseBytes(t *testing.T) {
	tests := []struct {
		name    string
		in      int64
		want    int64
		wantErr bool
	}{
		{"zero uses default", 0, DefaultMaxResponseBytes, false},
		{"positive kept", 42, 42, false},
		{"negative rejected", -1, 0, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ResolveMaxResponseBytes(tt.in)
			if (err != nil) != tt.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, tt.wantErr)
			}
			if got != tt.want {
				t.Errorf("got %d, want %d", got, tt.want)
			}
		})
	}
}

func TestNewHTTPService_NegativeMaxResponseBytesRejected(t *testing.T) {
	_, err := NewHTTPService(context.Background(), &http.Client{}, WithMaxResponseBytes(-5))
	if err == nil {
		t.Fatal("expected error for negative max_response_bytes")
	}
}

func TestHTTPService_ResponseSizeLimit(t *testing.T) {
	const limit = 16

	tests := []struct {
		name     string
		bodySize int
		chunked  bool
		want     string
	}{
		{"below limit", limit - 1, false, "ok:15"},
		{"exactly at limit", limit, false, "ok:16"},
		{"over limit with content-length", limit + 1, false, "err:" + ErrResponseTooLarge.Error()},
		{"over limit chunked", limit * 4, true, "err:" + ErrResponseTooLarge.Error()},
		{"at limit chunked", limit, true, "ok:16"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body := strings.Repeat("x", tt.bodySize)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if tt.chunked {
					// Flushing before the full body is written forces chunked
					// transfer encoding, so no Content-Length is sent.
					half := len(body) / 2
					_, _ = w.Write([]byte(body[:half]))
					w.(http.Flusher).Flush()
					_, _ = w.Write([]byte(body[half:]))
					return
				}
				_, _ = w.Write([]byte(body))
			}))
			defer server.Close()

			svc, err := NewHTTPService(context.Background(), server.Client(), WithMaxResponseBytes(limit))
			if err != nil {
				t.Fatalf("NewHTTPService: %v", err)
			}

			got := runLuaHTTP(t, svc, resultScript(`http.get("`+server.URL+`")`))
			if !strings.HasPrefix(got, tt.want) {
				t.Errorf("result = %q, want prefix %q", got, tt.want)
			}
		})
	}
}

func TestHTTPService_ResponseSizeLimitAppliesToAllMethods(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("y", 64)))
	}))
	defer server.Close()

	svc, err := NewHTTPService(context.Background(), server.Client(), WithMaxResponseBytes(8))
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}

	calls := map[string]string{
		"get":     `http.get("` + server.URL + `")`,
		"post":    `http.post("` + server.URL + `", "body")`,
		"request": `http.request("PUT", "` + server.URL + `", "body")`,
	}
	for name, expr := range calls {
		t.Run(name, func(t *testing.T) {
			got := runLuaHTTP(t, svc, resultScript(expr))
			if !strings.Contains(got, ErrResponseTooLarge.Error()) {
				t.Errorf("result = %q, want truncation error", got)
			}
		})
	}
}

func TestHTTPService_DefaultResponseSizeLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(strings.Repeat("z", int(DefaultMaxResponseBytes)+1)))
	}))
	defer server.Close()

	svc, err := NewHTTPService(context.Background(), server.Client())
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}

	got := runLuaHTTP(t, svc, resultScript(`http.get("`+server.URL+`")`))
	if !strings.Contains(got, ErrResponseTooLarge.Error()) {
		t.Errorf("result = %q, want default limit to reject a body over 1 MiB", got)
	}
}

// failingTransport fails the test if any request reaches the network layer.
type failingTransport struct{ t *testing.T }

func (f failingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	f.t.Errorf("unexpected request to %s", req.URL)
	return nil, http.ErrNotSupported
}

func TestHTTPService_NonHTTPSchemesRejected(t *testing.T) {
	urls := []string{
		"file:///etc/passwd",
		"ftp://ftp.example.com/data",
		"gopher://internal.example:70/",
		"javascript:alert(1)",
	}

	svc, err := NewHTTPService(context.Background(), &http.Client{Transport: failingTransport{t}})
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}

	for _, u := range urls {
		t.Run(u, func(t *testing.T) {
			got := runLuaHTTP(t, svc, resultScript(`http.get("`+u+`")`))
			if !strings.Contains(got, "is not allowed (must be http or https)") {
				t.Errorf("result = %q, want scheme rejection", got)
			}
		})
	}
}

func TestHTTPService_SchemeCheckIsCaseInsensitive(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	svc, err := NewHTTPService(context.Background(), server.Client())
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}

	upper := "HTTP://" + strings.TrimPrefix(server.URL, "http://")
	if got := runLuaHTTP(t, svc, resultScript(`http.get("`+upper+`")`)); got != "ok:2" {
		t.Errorf("result = %q, want ok:2", got)
	}
}

func TestHTTPService_ResponseHasNoErrorFieldWithinLimit(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Test", "1")
		_, _ = w.Write([]byte("hello"))
	}))
	defer server.Close()

	svc, err := NewHTTPService(context.Background(), server.Client(), WithMaxResponseBytes(5))
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}

	L := NewSandboxedState()
	defer L.Close()
	svc.Register(L)
	if err := L.DoString(`resp = http.get("` + server.URL + `")`); err != nil {
		t.Fatalf("DoString: %v", err)
	}
	resp, ok := L.GetGlobal("resp").(*lua.LTable)
	if !ok {
		t.Fatalf("resp is %s, want table", L.GetGlobal("resp").Type())
	}
	if got := resp.RawGetString("body").String(); got != "hello" {
		t.Errorf("body = %q, want hello", got)
	}
	if v := resp.RawGetString("error"); v != lua.LNil {
		t.Errorf("error field = %v, want nil", v)
	}
	if got := resp.RawGetString("headers").(*lua.LTable).RawGetString("X-Test").String(); got != "1" {
		t.Errorf("X-Test header = %q, want 1", got)
	}
}
