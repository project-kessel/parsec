package lua

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	lua "github.com/yuin/gopher-lua"
)

func TestHTTPService_WithRequestOptions(t *testing.T) {
	// Create a test server that checks for auth header
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth := r.Header.Get("Authorization")
		if auth != "Bearer auto-added-token" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("unauthorized"))
			return
		}

		// Check for custom header added by Lua
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

	// Create HTTP service with request options that adds auth header
	service := NewHTTPServiceWithConfig(HTTPServiceConfig{
		Timeout: 5 * time.Second,
		RequestOptions: func(req *http.Request) error {
			// Automatically add authorization header
			req.Header.Set("Authorization", "Bearer auto-added-token")
			return nil
		},
	})
	service.Register(L)

	// Lua script adds its own custom header
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

	// Create HTTP service with request options that returns an error
	service := NewHTTPServiceWithConfig(HTTPServiceConfig{
		Timeout: 5 * time.Second,
		RequestOptions: func(req *http.Request) error {
			return http.ErrServerClosed // arbitrary error
		},
	})
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
	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check if query param was added
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

	// Create HTTP service that adds API key as query param
	service := NewHTTPServiceWithConfig(HTTPServiceConfig{
		Timeout: 5 * time.Second,
		RequestOptions: func(req *http.Request) error {
			q := req.URL.Query()
			q.Add("api_key", "secret123")
			req.URL.RawQuery = q.Encode()
			return nil
		},
	})
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

	// Create a test server
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Check auth header is present
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

	// Create HTTP service that adds auth to all requests
	service := NewHTTPServiceWithConfig(HTTPServiceConfig{
		Timeout: 5 * time.Second,
		RequestOptions: func(req *http.Request) error {
			req.Header.Set("Authorization", "Bearer token")
			return nil
		},
	})
	service.Register(L)

	// Test GET
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

	// Test POST
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

	// Test generic request
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
