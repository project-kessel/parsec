package lua

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	lua "github.com/yuin/gopher-lua"
)

func TestHTTPService_Get_RelativeWithBaseURL(t *testing.T) {
	var gotURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	service, err := NewHTTPService(context.Background(), &http.Client{Timeout: 5 * time.Second},
		WithBaseURL(server.URL))
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	service.Register(L)

	if err := L.DoString(`
		local response, err = http.get("/v1/compliance")
		if response == nil then
			return "err:" .. tostring(err)
		end
		return response.status .. ":" .. response.body
	`); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	got := lua.LVAsString(L.Get(-1))
	if got != "200:ok" {
		t.Errorf("GET relative result = %q, want %q", got, "200:ok")
	}
	if gotURL != "/v1/compliance" {
		t.Errorf("request path = %q, want %q", gotURL, "/v1/compliance")
	}
}

func TestHTTPService_Post_RelativeWithBaseURL(t *testing.T) {
	var gotURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		if r.Method != http.MethodPost {
			t.Errorf("expected POST, got %s", r.Method)
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte("created"))
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	service, err := NewHTTPService(context.Background(), &http.Client{Timeout: 5 * time.Second},
		WithBaseURL(server.URL))
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	service.Register(L)

	if err := L.DoString(`
		local response, err = http.post("/v1/compliance", "body")
		if response == nil then
			return "err:" .. tostring(err)
		end
		return response.status .. ":" .. response.body
	`); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	got := lua.LVAsString(L.Get(-1))
	if got != "201:created" {
		t.Errorf("POST relative result = %q, want %q", got, "201:created")
	}
	if gotURL != "/v1/compliance" {
		t.Errorf("request path = %q, want %q", gotURL, "/v1/compliance")
	}
}

func TestHTTPService_Request_RelativeWithBaseURL(t *testing.T) {
	var gotURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		if r.Method != http.MethodPut {
			t.Errorf("expected PUT, got %s", r.Method)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("updated"))
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	service, err := NewHTTPService(context.Background(), &http.Client{Timeout: 5 * time.Second},
		WithBaseURL(server.URL))
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	service.Register(L)

	if err := L.DoString(`
		local response, err = http.request("PUT", "/v1/compliance", "data")
		if response == nil then
			return "err:" .. tostring(err)
		end
		return response.status .. ":" .. response.body
	`); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	got := lua.LVAsString(L.Get(-1))
	if got != "200:updated" {
		t.Errorf("request relative result = %q, want %q", got, "200:updated")
	}
	if gotURL != "/v1/compliance" {
		t.Errorf("request path = %q, want %q", gotURL, "/v1/compliance")
	}
}

func TestHTTPService_Get_RelativeWithBaseURL_PreservesQuery(t *testing.T) {
	var gotURL string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotURL = r.URL.String()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	service, err := NewHTTPService(context.Background(), &http.Client{Timeout: 5 * time.Second},
		WithBaseURL(server.URL))
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	service.Register(L)

	if err := L.DoString(`
		local response, err = http.get("/v1/compliance?x=1")
		if response == nil then
			return "err:" .. tostring(err)
		end
		return response.status .. ":" .. response.body
	`); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	got := lua.LVAsString(L.Get(-1))
	if got != "200:ok" {
		t.Errorf("GET query result = %q, want %q", got, "200:ok")
	}
	if gotURL != "/v1/compliance?x=1" {
		t.Errorf("request path = %q, want %q", gotURL, "/v1/compliance?x=1")
	}
}

func TestHTTPService_AbsoluteURLIgnoresBaseURL(t *testing.T) {
	var hits int
	ignored := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		t.Error("base_url host should not be hit for an absolute Lua URL")
		w.WriteHeader(http.StatusTeapot)
	}))
	defer ignored.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("absolute"))
	}))
	defer target.Close()

	L := lua.NewState()
	defer L.Close()

	service, err := NewHTTPService(context.Background(), &http.Client{Timeout: 5 * time.Second},
		WithBaseURL(ignored.URL))
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	service.Register(L)

	script := `
		local response, err = http.get("` + target.URL + `/v1/other")
		if response == nil then
			return "err:" .. tostring(err)
		end
		return response.status .. ":" .. response.body
	`
	if err := L.DoString(script); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	got := lua.LVAsString(L.Get(-1))
	if got != "200:absolute" {
		t.Errorf("absolute URL result = %q, want %q", got, "200:absolute")
	}
	if hits != 0 {
		t.Errorf("base_url host was hit %d times, want 0", hits)
	}
}

func TestHTTPService_RelativeWithoutBaseURLErrors(t *testing.T) {
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	service, err := NewHTTPService(context.Background(), &http.Client{Timeout: 5 * time.Second})
	if err != nil {
		t.Fatalf("failed to create http service: %v", err)
	}
	service.Register(L)

	if err := L.DoString(`
		local response, err = http.get("/v1/compliance")
		if response == nil and err ~= nil and err ~= "" then
			return "error"
		end
		return "no-error"
	`); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	got := lua.LVAsString(L.Get(-1))
	if got != "error" {
		t.Errorf("relative URL without base_url = %q, want %q", got, "error")
	}
	if hits != 0 {
		t.Errorf("server was hit %d times, want 0", hits)
	}
}

func TestHTTPService_ProtocolRelativeURLRejected(t *testing.T) {
	hits := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
	}))
	defer server.Close()

	L := lua.NewState()
	defer L.Close()

	service, err := NewHTTPService(context.Background(), &http.Client{Timeout: 5 * time.Second},
		WithBaseURL(server.URL))
	if err != nil {
		t.Fatalf("NewHTTPService: %v", err)
	}
	service.Register(L)

	if err := L.DoString(`
		local response, err = http.get("//attacker.example/path")
		if response == nil and err ~= nil and err ~= "" then
			return "error"
		end
		return "no-error"
	`); err != nil {
		t.Fatalf("script execution failed: %v", err)
	}

	got := lua.LVAsString(L.Get(-1))
	if got != "error" {
		t.Errorf("protocol-relative URL = %q, want %q", got, "error")
	}
	if hits != 0 {
		t.Errorf("server was hit %d times, want 0", hits)
	}
}

func TestNewHTTPService_InvalidBaseURLRejected(t *testing.T) {
	_, err := NewHTTPService(context.Background(), &http.Client{}, WithBaseURL("not a url"))
	if err == nil {
		t.Fatal("expected error for unparseable base_url, got nil")
	}
}
