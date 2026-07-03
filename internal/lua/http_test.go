package lua

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
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
