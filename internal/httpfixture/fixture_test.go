package httpfixture

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRuleBasedProvider_ExactMatch(t *testing.T) {
	rules := []HTTPFixtureRule{
		{
			Request: FixtureRequest{
				Method: "GET",
				URL:    "https://api.example.com/user/alice",
			},
			Response: Fixture{
				StatusCode: 200,
				Headers:    map[string]string{"Content-Type": "application/json"},
				Body:       `{"username": "alice"}`,
			},
		},
	}

	provider := NewRuleBasedProvider(rules)

	req := httptest.NewRequest("GET", "https://api.example.com/user/alice", nil)
	fixture := provider.GetFixture(req)

	if fixture == nil {
		t.Fatal("expected fixture, got nil")
	}

	if fixture.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", fixture.StatusCode)
	}

	if fixture.Body != `{"username": "alice"}` {
		t.Errorf("Body = %q, want %q", fixture.Body, `{"username": "alice"}`)
	}
}

func TestRuleBasedProvider_PatternMatch(t *testing.T) {
	rules := []HTTPFixtureRule{
		{
			Request: FixtureRequest{
				Method:  "GET",
				URL:     "https://api.example.com/user/.*",
				URLType: "pattern",
			},
			Response: Fixture{
				StatusCode: 200,
				Body:       `{"user": "any"}`,
			},
		},
	}

	provider := NewRuleBasedProvider(rules)

	tests := []struct {
		url       string
		wantMatch bool
	}{
		{"https://api.example.com/user/alice", true},
		{"https://api.example.com/user/bob", true},
		{"https://api.example.com/user/123", true},
		{"https://api.example.com/users", false},
		{"https://api.example.com/other", false},
	}

	for _, tt := range tests {
		t.Run(tt.url, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.url, nil)
			fixture := provider.GetFixture(req)

			if tt.wantMatch && fixture == nil {
				t.Error("expected fixture, got nil")
			}
			if !tt.wantMatch && fixture != nil {
				t.Error("expected nil, got fixture")
			}
		})
	}
}

func TestRuleBasedProvider_MethodMatch(t *testing.T) {
	rules := []HTTPFixtureRule{
		{
			Request: FixtureRequest{
				Method: "POST",
				URL:    "https://api.example.com/create",
			},
			Response: Fixture{
				StatusCode: 201,
				Body:       `{"created": true}`,
			},
		},
	}

	provider := NewRuleBasedProvider(rules)

	// POST should match
	req := httptest.NewRequest("POST", "https://api.example.com/create", nil)
	fixture := provider.GetFixture(req)
	if fixture == nil {
		t.Fatal("expected fixture for POST, got nil")
	}

	// GET should not match
	req = httptest.NewRequest("GET", "https://api.example.com/create", nil)
	fixture = provider.GetFixture(req)
	if fixture != nil {
		t.Error("expected nil for GET, got fixture")
	}
}

func TestRuleBasedProvider_HeaderMatch(t *testing.T) {
	rules := []HTTPFixtureRule{
		{
			Request: FixtureRequest{
				Method: "GET",
				URL:    "https://api.example.com/data",
				Headers: map[string]string{
					"Authorization": "Bearer token123",
				},
			},
			Response: Fixture{
				StatusCode: 200,
				Body:       `{"authorized": true}`,
			},
		},
	}

	provider := NewRuleBasedProvider(rules)

	// With matching header
	req := httptest.NewRequest("GET", "https://api.example.com/data", nil)
	req.Header.Set("Authorization", "Bearer token123")
	fixture := provider.GetFixture(req)
	if fixture == nil {
		t.Fatal("expected fixture with matching header, got nil")
	}

	// Without header
	req = httptest.NewRequest("GET", "https://api.example.com/data", nil)
	fixture = provider.GetFixture(req)
	if fixture != nil {
		t.Error("expected nil without header, got fixture")
	}

	// With wrong header
	req = httptest.NewRequest("GET", "https://api.example.com/data", nil)
	req.Header.Set("Authorization", "Bearer wrong")
	fixture = provider.GetFixture(req)
	if fixture != nil {
		t.Error("expected nil with wrong header, got fixture")
	}
}

func TestRuleBasedProvider_WildcardMethod(t *testing.T) {
	rules := []HTTPFixtureRule{
		{
			Request: FixtureRequest{
				Method: "*",
				URL:    "https://api.example.com/any",
			},
			Response: Fixture{
				StatusCode: 200,
				Body:       `{"any": "method"}`,
			},
		},
	}

	provider := NewRuleBasedProvider(rules)

	methods := []string{"GET", "POST", "PUT", "DELETE", "PATCH"}
	for _, method := range methods {
		t.Run(method, func(t *testing.T) {
			req := httptest.NewRequest(method, "https://api.example.com/any", nil)
			fixture := provider.GetFixture(req)
			if fixture == nil {
				t.Errorf("expected fixture for %s, got nil", method)
			}
		})
	}
}

func TestRuleBasedProvider_NoMatch(t *testing.T) {
	rules := []HTTPFixtureRule{
		{
			Request: FixtureRequest{
				Method: "GET",
				URL:    "https://api.example.com/user/alice",
			},
			Response: Fixture{
				StatusCode: 200,
				Body:       `{"username": "alice"}`,
			},
		},
	}

	provider := NewRuleBasedProvider(rules)

	req := httptest.NewRequest("GET", "https://api.example.com/user/bob", nil)
	fixture := provider.GetFixture(req)

	if fixture != nil {
		t.Error("expected nil for non-matching request, got fixture")
	}
}

func TestMapProvider(t *testing.T) {
	fixtures := map[string]*Fixture{
		"GET https://api.example.com/user/alice": {
			StatusCode: 200,
			Body:       `{"username": "alice"}`,
		},
		"POST https://api.example.com/create": {
			StatusCode: 201,
			Body:       `{"created": true}`,
		},
	}

	provider := NewMapProvider(fixtures)

	// Match GET
	req := httptest.NewRequest("GET", "https://api.example.com/user/alice", nil)
	fixture := provider.GetFixture(req)
	if fixture == nil {
		t.Fatal("expected fixture for GET, got nil")
	}
	if fixture.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", fixture.StatusCode)
	}

	// Match POST
	req = httptest.NewRequest("POST", "https://api.example.com/create", nil)
	fixture = provider.GetFixture(req)
	if fixture == nil {
		t.Fatal("expected fixture for POST, got nil")
	}
	if fixture.StatusCode != 201 {
		t.Errorf("StatusCode = %d, want 201", fixture.StatusCode)
	}

	// No match
	req = httptest.NewRequest("GET", "https://api.example.com/other", nil)
	fixture = provider.GetFixture(req)
	if fixture != nil {
		t.Error("expected nil for non-matching request, got fixture")
	}
}

func TestFuncProvider(t *testing.T) {
	provider := NewFuncProvider(func(req *http.Request) *Fixture {
		if strings.HasPrefix(req.URL.Path, "/user/") {
			userID := strings.TrimPrefix(req.URL.Path, "/user/")
			return &Fixture{
				StatusCode: 200,
				Body:       `{"id": "` + userID + `"}`,
			}
		}
		return nil
	})

	// Match with dynamic content
	req := httptest.NewRequest("GET", "https://api.example.com/user/alice", nil)
	fixture := provider.GetFixture(req)
	if fixture == nil {
		t.Fatal("expected fixture, got nil")
	}
	if fixture.Body != `{"id": "alice"}` {
		t.Errorf("Body = %q, want %q", fixture.Body, `{"id": "alice"}`)
	}

	// Another user
	req = httptest.NewRequest("GET", "https://api.example.com/user/bob", nil)
	fixture = provider.GetFixture(req)
	if fixture == nil {
		t.Fatal("expected fixture, got nil")
	}
	if fixture.Body != `{"id": "bob"}` {
		t.Errorf("Body = %q, want %q", fixture.Body, `{"id": "bob"}`)
	}

	// No match
	req = httptest.NewRequest("GET", "https://api.example.com/other", nil)
	fixture = provider.GetFixture(req)
	if fixture != nil {
		t.Error("expected nil, got fixture")
	}
}

func TestTransport_WithFixture(t *testing.T) {
	provider := NewMapProvider(map[string]*Fixture{
		"GET https://api.example.com/data": {
			StatusCode: 200,
			Headers:    map[string]string{"Content-Type": "application/json"},
			Body:       `{"result": "success"}`,
		},
	})

	transport := NewTransport(TransportConfig{
		Provider: provider,
		Strict:   true,
	})

	client := &http.Client{Transport: transport}

	resp, err := client.Get("https://api.example.com/data")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != 200 {
		t.Errorf("StatusCode = %d, want 200", resp.StatusCode)
	}

	if ct := resp.Header.Get("Content-Type"); ct != "application/json" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/json")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("failed to read body: %v", err)
	}

	if string(body) != `{"result": "success"}` {
		t.Errorf("Body = %q, want %q", string(body), `{"result": "success"}`)
	}
}

func TestTransport_StrictMode(t *testing.T) {
	provider := NewMapProvider(map[string]*Fixture{})

	transport := NewTransport(TransportConfig{
		Provider: provider,
		Strict:   true,
	})

	client := &http.Client{Transport: transport}

	_, err := client.Get("https://api.example.com/missing")
	if err == nil {
		t.Error("expected error in strict mode, got nil")
	}

	if !strings.Contains(err.Error(), "no fixture provided") {
		t.Errorf("error = %q, want error containing 'no fixture provided'", err.Error())
	}
}

func TestTransport_WithFallback(t *testing.T) {
	// Create a test server for fallback
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("real response"))
	}))
	defer server.Close()

	provider := NewMapProvider(map[string]*Fixture{
		"GET https://api.example.com/fixture": {
			StatusCode: 200,
			Body:       "fixture response",
		},
	})

	transport := NewTransport(TransportConfig{
		Provider: provider,
		Fallback: http.DefaultTransport,
		Strict:   false,
	})

	client := &http.Client{Transport: transport}

	// Request with fixture should use fixture
	resp, err := client.Get("https://api.example.com/fixture")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "fixture response" {
		t.Errorf("expected fixture response, got %q", string(body))
	}

	// Request without fixture should fall back to real HTTP
	resp, err = client.Get(server.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, _ = io.ReadAll(resp.Body)
	if string(body) != "real response" {
		t.Errorf("expected real response, got %q", string(body))
	}
}

func TestTransport_WithDelay(t *testing.T) {
	delay := 100 * time.Millisecond

	provider := NewMapProvider(map[string]*Fixture{
		"GET https://api.example.com/slow": {
			StatusCode: 200,
			Body:       "delayed",
			Delay:      &delay,
		},
	})

	transport := NewTransport(TransportConfig{
		Provider: provider,
		Strict:   true,
	})

	client := &http.Client{Transport: transport}

	start := time.Now()
	resp, err := client.Get("https://api.example.com/slow")
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if elapsed < delay {
		t.Errorf("expected delay of at least %v, got %v", delay, elapsed)
	}
}
