package lua

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	lua "github.com/yuin/gopher-lua"
)

func TestNewHTTPService_NilClientRejected(t *testing.T) {
	service, err := NewHTTPService(context.Background(), nil)
	if err == nil {
		t.Fatal("expected error for nil client, got nil")
	}
	if service != nil {
		t.Errorf("expected nil service on error, got %+v", service)
	}
}

func TestHTTPService_Get(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "GET" {
			t.Errorf("expected GET request, got %s", r.Method)
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"message": "success",
		})
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	service, err := NewHTTPService(context.Background(), client)
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	service.Register(L)

	script := `
		local response = http.get("` + server.URL + `")
		return response.status .. ":" .. response.body
	`

	if err := L.DoString(script); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	result := L.Get(-1)
	L.Pop(1)

	got := lua.LVAsString(result)
	if got != `200:{"message":"success"}`+"\n" {
		t.Errorf("GET result = %q, want %q", got, `200:{"message":"success"}`+"\n")
	}
}

func TestHTTPService_GetWithHeaders(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer test-token" {
			t.Errorf("expected Authorization header, got %q", auth)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("authenticated"))
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	service, err := NewHTTPService(context.Background(), client)
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	service.Register(L)

	script := `
		local headers = {["Authorization"] = "Bearer test-token"}
		local response = http.get("` + server.URL + `", headers)
		return response.body
	`

	if err := L.DoString(script); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	result := L.Get(-1)
	L.Pop(1)

	if lua.LVAsString(result) != "authenticated" {
		t.Errorf("GET with headers result = %q, want %q", lua.LVAsString(result), "authenticated")
	}
}

func TestHTTPService_Post(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" {
			t.Errorf("expected POST request, got %s", r.Method)
		}

		contentType := r.Header.Get("Content-Type")
		if contentType != "application/json" {
			t.Errorf("expected Content-Type header, got %q", contentType)
		}

		var data map[string]string
		if err := json.NewDecoder(r.Body).Decode(&data); err != nil {
			t.Errorf("failed to decode body: %v", err)
		}

		if data["action"] != "create" {
			t.Errorf("expected action=create, got %q", data["action"])
		}

		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(map[string]string{
			"result": "created",
		})
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	service, err := NewHTTPService(context.Background(), client)
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	service.Register(L)

	// Also register JSON service for encoding
	jsonService := NewJSONService()
	jsonService.Register(L)

	script := `
		local body = json.encode({action = "create"})
		local headers = {["Content-Type"] = "application/json"}
		local response = http.post("` + server.URL + `", body, headers)
		return response.status .. ":" .. response.body
	`

	if err := L.DoString(script); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	result := L.Get(-1)
	L.Pop(1)

	got := lua.LVAsString(result)
	if got != `201:{"result":"created"}`+"\n" {
		t.Errorf("POST result = %q, want %q", got, `201:{"result":"created"}`+"\n")
	}
}

func TestHTTPService_Request(t *testing.T) {
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "PUT" {
			t.Errorf("expected PUT request, got %s", r.Method)
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("updated"))
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	service, err := NewHTTPService(context.Background(), client)
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	service.Register(L)

	script := `
		local response = http.request("PUT", "` + server.URL + `", "data")
		return response.status .. ":" .. response.body
	`

	if err := L.DoString(script); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	result := L.Get(-1)
	L.Pop(1)

	if lua.LVAsString(result) != "200:updated" {
		t.Errorf("PUT request result = %q, want %q", lua.LVAsString(result), "200:updated")
	}
}

func TestHTTPService_GetError(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	client := &http.Client{Timeout: 1 * time.Second}
	service, err := NewHTTPService(context.Background(), client)
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	service.Register(L)

	// Use an invalid URL
	script := `
		local response, err = http.get("http://invalid-domain-that-does-not-exist-12345.com")
		if response == nil and err ~= nil then
			return "error"
		end
		return "no-error"
	`

	if err := L.DoString(script); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	result := L.Get(-1)
	L.Pop(1)

	if lua.LVAsString(result) != "error" {
		t.Errorf("expected error for invalid URL")
	}
}

func TestHTTPService_StatusCodes(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
	}{
		{"200 OK", http.StatusOK},
		{"201 Created", http.StatusCreated},
		{"204 No Content", http.StatusNoContent},
		{"400 Bad Request", http.StatusBadRequest},
		{"401 Unauthorized", http.StatusUnauthorized},
		{"404 Not Found", http.StatusNotFound},
		{"500 Internal Server Error", http.StatusInternalServerError},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tt.statusCode)
				_, _ = w.Write([]byte("body"))
			}))
			defer server.Close()

			L := lua.NewState()
			defer L.Close()

			client := &http.Client{Timeout: 5 * time.Second}
			service, err := NewHTTPService(context.Background(), client)
			if err != nil {
				t.Fatalf("failed to create http service: %v", err)
			}
			service.Register(L)

			script := `
				local response = http.get("` + server.URL + `")
				return response.status
			`

			if err := L.DoString(script); err != nil {
				t.Fatalf("script execution failed: %v", err)
			}

			result := L.Get(-1)
			L.Pop(1)

			if result.Type() != lua.LTNumber {
				t.Fatalf("expected number result, got %s", result.Type())
			}

			status := int(lua.LVAsNumber(result))
			if status != tt.statusCode {
				t.Errorf("status = %d, want %d", status, tt.statusCode)
			}
		})
	}
}

func TestHTTPService_ResponseHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Custom-Header", "custom-value")
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	service, err := NewHTTPService(context.Background(), client)
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	service.Register(L)

	script := `
		local response = http.get("` + server.URL + `")
		return response.headers["X-Custom-Header"] .. ":" .. response.headers["Content-Type"]
	`

	if err := L.DoString(script); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	result := L.Get(-1)
	L.Pop(1)

	expected := "custom-value:application/json"
	if lua.LVAsString(result) != expected {
		t.Errorf("headers = %q, want %q", lua.LVAsString(result), expected)
	}
}

type ctxKey struct{}

type capturingTransport struct {
	capturedCtx context.Context
	wrapped     http.RoundTripper
}

func (ct *capturingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ct.capturedCtx = req.Context()
	return ct.wrapped.RoundTrip(req)
}

func TestHTTPService_PropagatesContext(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	tests := []struct {
		name   string
		script string
	}{
		{"get", `http.get("` + server.URL + `")`},
		{"post", `http.post("` + server.URL + `", "body")`},
		{"request", `http.request("PUT", "` + server.URL + `", "body")`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ct := &capturingTransport{wrapped: http.DefaultTransport}
			ctx := context.WithValue(context.Background(), ctxKey{}, "trace-123")

			client := &http.Client{Timeout: 5 * time.Second, Transport: ct}
			svc, err := NewHTTPService(ctx, client)
			if err != nil {
				t.Fatalf("failed to create http service: %v", err)
			}
			L := lua.NewState()
			defer L.Close()
			svc.Register(L)

			if err := L.DoString(tt.script); err != nil {
				t.Fatalf("script execution failed: %v", err)
			}

			if ct.capturedCtx == nil {
				t.Fatal("transport did not capture a request context")
			}
			val, ok := ct.capturedCtx.Value(ctxKey{}).(string)
			if !ok || val != "trace-123" {
				t.Errorf("context value not propagated: got %q, want %q", val, "trace-123")
			}
		})
	}
}

func TestHTTPService_CancelledContextReturnsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	methods := []struct {
		name   string
		script string
	}{
		{"get", `
			local resp, err = http.get("` + server.URL + `")
			if resp == nil and err ~= nil then return "error" end
			return "no-error"
		`},
		{"post", `
			local resp, err = http.post("` + server.URL + `", "body")
			if resp == nil and err ~= nil then return "error" end
			return "no-error"
		`},
		{"request", `
			local resp, err = http.request("DELETE", "` + server.URL + `")
			if resp == nil and err ~= nil then return "error" end
			return "no-error"
		`},
	}

	for _, tt := range methods {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(context.Background())
			cancel()

			client := &http.Client{Timeout: 5 * time.Second}
			svc, err := NewHTTPService(ctx, client)
			if err != nil {
				t.Fatalf("failed to create http service: %v", err)
			}
			L := lua.NewState()
			defer L.Close()
			svc.Register(L)

			if err := L.DoString(tt.script); err != nil {
				t.Fatalf("script execution failed: %v", err)
			}

			result := lua.LVAsString(L.Get(-1))
			L.Pop(1)
			if result != "error" {
				t.Errorf("expected error from cancelled context, got %q", result)
			}
		})
	}
}

func TestHTTPService_RequestOptionsError_AllMethods(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	methods := []struct {
		name   string
		script string
	}{
		{"post", `
			local resp, err = http.post("` + server.URL + `", "body")
			if resp == nil and err ~= nil then return "error" end
			return "no-error"
		`},
		{"request", `
			local resp, err = http.request("PUT", "` + server.URL + `", "body")
			if resp == nil and err ~= nil then return "error" end
			return "no-error"
		`},
	}

	for _, tt := range methods {
		t.Run(tt.name, func(t *testing.T) {
			client := &http.Client{Timeout: 5 * time.Second}
			svc, err := NewHTTPService(context.Background(), client,
				WithRequestOptions(func(req *http.Request) error {
					return http.ErrServerClosed
				}),
			)
			if err != nil {
				t.Fatalf("failed to create http service: %v", err)
			}
			L := lua.NewState()
			defer L.Close()
			svc.Register(L)

			if err := L.DoString(tt.script); err != nil {
				t.Fatalf("script execution failed: %v", err)
			}

			result := lua.LVAsString(L.Get(-1))
			L.Pop(1)
			if result != "error" {
				t.Errorf("expected error from request options, got %q", result)
			}
		})
	}
}

func TestHTTPService_Request_NoBody(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "DELETE" {
			t.Errorf("expected DELETE, got %s", r.Method)
		}
		if r.ContentLength > 0 {
			t.Error("expected no body for DELETE without body")
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	svc, err := NewHTTPService(context.Background(), client)
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	svc.Register(L)

	script := `
		local response = http.request("DELETE", "` + server.URL + `")
		return response.status
	`
	if err := L.DoString(script); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	status := int(lua.LVAsNumber(L.Get(-1)))
	L.Pop(1)
	if status != http.StatusNoContent {
		t.Errorf("status=%d, want %d", status, http.StatusNoContent)
	}
}

func TestHTTPService_Request_WithHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Custom") != "value" {
			t.Errorf("X-Custom=%q, want 'value'", r.Header.Get("X-Custom"))
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	svc, err := NewHTTPService(context.Background(), client)
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	svc.Register(L)

	script := `
		local headers = {["X-Custom"] = "value"}
		local response = http.request("PATCH", "` + server.URL + `", "data", headers)
		return response.body
	`
	if err := L.DoString(script); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	result := lua.LVAsString(L.Get(-1))
	L.Pop(1)
	if result != "ok" {
		t.Errorf("body=%q, want 'ok'", result)
	}
}

func TestResolveRequestURL(t *testing.T) {
	t.Parallel()

	base := "https://entitlements.example.com"
	svc := &HTTPService{
		ctx:     context.Background(),
		client:  &http.Client{},
		baseURL: base,
	}

	tests := []struct {
		name    string
		svc     *HTTPService
		raw     string
		want    string
		wantErr string
	}{
		{
			name: "absolute unchanged",
			svc:  svc,
			raw:  "https://other.example/v1/data",
			want: "https://other.example/v1/data",
		},
		{
			name: "relative joined",
			svc:  svc,
			raw:  "/v1/compliance",
			want: "https://entitlements.example.com/v1/compliance",
		},
		{
			name: "relative with query",
			svc:  svc,
			raw:  "/v1/compliance?x=1",
			want: "https://entitlements.example.com/v1/compliance?x=1",
		},
		{
			name:    "relative without base",
			svc:     &HTTPService{ctx: context.Background(), client: &http.Client{}},
			raw:     "/v1/compliance",
			wantErr: "requires a configured base_url",
		},
		{
			name:    "protocol relative rejected",
			svc:     svc,
			raw:     "//attacker.example/path",
			wantErr: "with host but no scheme",
		},
		{
			name:    "invalid url parse",
			svc:     svc,
			raw:     "http://%zz",
			wantErr: "invalid url",
		},
		{
			name:    "invalid stored base url",
			svc:     &HTTPService{ctx: context.Background(), client: &http.Client{}, baseURL: "ftp://host.example"},
			raw:     "/v1/compliance",
			wantErr: "scheme must be http or https",
		},
		{
			name:    "stored base url with user info",
			svc:     &HTTPService{ctx: context.Background(), client: &http.Client{}, baseURL: "https://user:pass@host.example"},
			raw:     "/v1/compliance",
			wantErr: "must not include user info",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := tt.svc.resolveRequestURL(tt.raw)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("error = %q, want substring %q", err.Error(), tt.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("resolveRequestURL(%q) = %q, want %q", tt.raw, got, tt.want)
			}
		})
	}
}

func TestHTTPService_WithRequestOptions(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer auto-added-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))
			return
		}

		customHeader := r.Header.Get("X-Custom")
		if customHeader != "from-lua" {
			w.WriteHeader(http.StatusBadRequest)
			_, _ = w.Write([]byte("missing custom header"))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("authenticated"))
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	service, err := NewHTTPService(context.Background(), client,
		WithRequestOptions(func(req *http.Request) error {
			req.Header.Set("Authorization", "Bearer auto-added-token")
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	service.Register(L)

	script := `
		local headers = {["X-Custom"] = "from-lua"}
		local response = http.get("` + server.URL + `", headers)
		return response.status .. ":" .. response.body
	`

	if err := L.DoString(script); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	result := L.Get(-1)
	L.Pop(1)

	expected := "200:authenticated"
	if lua.LVAsString(result) != expected {
		t.Errorf("result = %q, want %q", lua.LVAsString(result), expected)
	}
}

func TestHTTPService_RequestOptionsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	service, err := NewHTTPService(context.Background(), client,
		WithRequestOptions(func(req *http.Request) error {
			return http.ErrServerClosed
		}),
	)
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	service.Register(L)

	script := `
		local response, err = http.get("` + server.URL + `")
		if response == nil and err ~= nil then
			return "error"
		end
		return "no-error"
	`

	if err := L.DoString(script); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	result := L.Get(-1)
	L.Pop(1)

	if lua.LVAsString(result) != "error" {
		t.Errorf("expected error when request options returns error")
	}
}

func TestHTTPService_RequestOptionsModifyURL(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("api_key") != "secret123" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("missing api key"))
			return
		}

		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("success"))
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	service, err := NewHTTPService(context.Background(), client,
		WithRequestOptions(func(req *http.Request) error {
			q := req.URL.Query()
			q.Add("api_key", "secret123")
			req.URL.RawQuery = q.Encode()
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	service.Register(L)

	script := `
		local response = http.get("` + server.URL + `/api/data")
		return response.status .. ":" .. response.body
	`

	if err := L.DoString(script); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	result := L.Get(-1)
	L.Pop(1)

	expected := "200:success"
	if lua.LVAsString(result) != expected {
		t.Errorf("result = %q, want %q", lua.LVAsString(result), expected)
	}
}

func TestHTTPService_RequestOptionsAllMethods(t *testing.T) {
	callCount := 0

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		callCount++
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	client := &http.Client{Timeout: 5 * time.Second}
	service, err := NewHTTPService(context.Background(), client,
		WithRequestOptions(func(req *http.Request) error {
			req.Header.Set("Authorization", "Bearer token")
			return nil
		}),
	)
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	service.Register(L)

	script := `
		local response = http.get("` + server.URL + `")
		return response.status
	`
	if err := L.DoString(script); err != nil {
		t.Fatalf("GET failed: %v", err)
	}
	status := L.ToInt(-1)
	L.Pop(1)
	if status != 200 {
		t.Errorf("GET status = %d, want 200", status)
	}

	script = `
		local response = http.post("` + server.URL + `", "data")
		return response.status
	`
	if err := L.DoString(script); err != nil {
		t.Fatalf("POST failed: %v", err)
	}
	status = L.ToInt(-1)
	L.Pop(1)
	if status != 200 {
		t.Errorf("POST status = %d, want 200", status)
	}

	script = `
		local response = http.request("PUT", "` + server.URL + `", "data")
		return response.status
	`
	if err := L.DoString(script); err != nil {
		t.Fatalf("PUT failed: %v", err)
	}
	status = L.ToInt(-1)
	L.Pop(1)
	if status != 200 {
		t.Errorf("PUT status = %d, want 200", status)
	}

	if callCount != 3 {
		t.Errorf("expected 3 successful calls, got %d", callCount)
	}
}

func TestHTTPService_ParseHeadersNonTableIgnored(t *testing.T) {
	var gotAuth string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	svc, err := NewHTTPService(context.Background(), &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}
	svc.Register(L)

	if err := L.DoString(`
		local response = http.get("` + server.URL + `", "not-a-table")
		return response.body
	`); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	if gotAuth != "" {
		t.Errorf("Authorization = %q, want empty when headers arg is not a table", gotAuth)
	}
	if lua.LVAsString(L.Get(-1)) != "ok" {
		t.Errorf("body = %q, want ok", lua.LVAsString(L.Get(-1)))
	}
}

func TestHTTPService_ParseHeadersIgnoresNonStringKeys(t *testing.T) {
	var gotCustom string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCustom = r.Header.Get("X-Custom")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	svc, err := NewHTTPService(context.Background(), &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}
	svc.Register(L)

	if err := L.DoString(`
		local headers = {[123] = "ignored", ["X-Custom"] = "value"}
		local response = http.get("` + server.URL + `", headers)
		return response.body
	`); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	if gotCustom != "value" {
		t.Errorf("X-Custom = %q, want value", gotCustom)
	}
}

type errorReader struct{}

func (errorReader) Read([]byte) (int, error) {
	return 0, fmt.Errorf("simulated read failure")
}

type badBodyTransport struct{}

func (badBodyTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Body:       io.NopCloser(errorReader{}),
		Header:     make(http.Header),
	}, nil
}

func TestHTTPService_ResponseBodyReadError(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	svc, err := NewHTTPService(context.Background(), &http.Client{
		Timeout:   5 * time.Second,
		Transport: badBodyTransport{},
	})
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}
	svc.Register(L)

	if err := L.DoString(`
		local response = http.get("https://example.invalid/data")
		if response.body ~= "" then
			return "body:" .. response.body
		end
		if response.error == nil or response.error == "" then
			return "missing-error"
		end
		return "error"
	`); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	if lua.LVAsString(L.Get(-1)) != "error" {
		t.Errorf("result = %q, want error", lua.LVAsString(L.Get(-1)))
	}
}

func TestHTTPService_Post_RelativeWithoutBaseURLErrors(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	svc, err := NewHTTPService(context.Background(), &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}
	svc.Register(L)

	if err := L.DoString(`
		local response, err = http.post("/v1/compliance", "body")
		if response == nil and err ~= nil and err ~= "" then
			return "error"
		end
		return "no-error"
	`); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	if lua.LVAsString(L.Get(-1)) != "error" {
		t.Error("expected error for relative POST without base_url")
	}
	if hits != 0 {
		t.Errorf("server hit %d times, want 0", hits)
	}
}

func TestHTTPService_Request_RelativeWithoutBaseURLErrors(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	svc, err := NewHTTPService(context.Background(), &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}
	svc.Register(L)

	if err := L.DoString(`
		local response, err = http.request("PUT", "/v1/compliance", "data")
		if response == nil and err ~= nil and err ~= "" then
			return "error"
		end
		return "no-error"
	`); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	if lua.LVAsString(L.Get(-1)) != "error" {
		t.Error("expected error for relative request without base_url")
	}
	if hits != 0 {
		t.Errorf("server hit %d times, want 0", hits)
	}
}

func TestHTTPService_Get_InvalidURLErrors(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	svc, err := NewHTTPService(context.Background(), &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}
	svc.Register(L)

	if err := L.DoString(`
		local response, err = http.get("http://%zz")
		if response == nil and err ~= nil and err ~= "" then
			return "error"
		end
		return "no-error"
	`); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	if lua.LVAsString(L.Get(-1)) != "error" {
		t.Error("expected error for malformed absolute URL")
	}
}

func TestHTTPService_Post_InvalidURLErrors(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	svc, err := NewHTTPService(context.Background(), &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}
	svc.Register(L)

	if err := L.DoString(`
		local response, err = http.post("http://%zz", "body")
		if response == nil and err ~= nil and err ~= "" then
			return "error"
		end
		return "no-error"
	`); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	if lua.LVAsString(L.Get(-1)) != "error" {
		t.Error("expected error for malformed absolute URL on POST")
	}
}

func TestHTTPService_Request_InvalidURLErrors(t *testing.T) {
	L := lua.NewState()
	defer L.Close()

	svc, err := NewHTTPService(context.Background(), &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}
	svc.Register(L)

	if err := L.DoString(`
		local response, err = http.request("PUT", "http://%zz", "body")
		if response == nil and err ~= nil and err ~= "" then
			return "error"
		end
		return "no-error"
	`); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	if lua.LVAsString(L.Get(-1)) != "error" {
		t.Error("expected error for malformed absolute URL on request")
	}
}

func TestHTTPService_Request_InvalidMethodErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	svc, err := NewHTTPService(context.Background(), &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}
	svc.Register(L)

	if err := L.DoString(`
		local response, err = http.request("BAD METHOD", "` + server.URL + `", "body")
		if response == nil and err ~= nil and err ~= "" then
			return "error"
		end
		return "no-error"
	`); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	if lua.LVAsString(L.Get(-1)) != "error" {
		t.Error("expected error for invalid HTTP method")
	}
}

func TestHTTPService_ResponseHeadersEmptyValuesSkipped(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header()["X-Empty"] = []string{}
		w.Header().Set("X-Present", "yes")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{}"))
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	svc, err := NewHTTPService(context.Background(), &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}
	svc.Register(L)

	if err := L.DoString(`
		local response = http.get("` + server.URL + `")
		local empty = response.headers["X-Empty"]
		local present = response.headers["X-Present"]
		if empty == nil and present == "yes" then
			return "ok"
		end
		return "bad"
	`); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	if lua.LVAsString(L.Get(-1)) != "ok" {
		t.Error("expected empty header values to be omitted from response table")
	}
}
