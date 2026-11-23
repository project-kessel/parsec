package datasource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/project-kessel/parsec/internal/httpclient"
	luaservices "github.com/project-kessel/parsec/internal/lua"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func aliceInput() *service.DataSourceInput {
	return &service.DataSourceInput{Subject: &trust.Result{Subject: "alice"}}
}

func TestLuaDataSource_Fetch_StdlibEscapesFail(t *testing.T) {
	tests := []struct {
		name string
		call string
	}{
		{"os.execute", `os.execute("id")`},
		{"os.getenv", `os.getenv("HOME")`},
		{"io.open", `io.open("/etc/passwd", "r")`},
		{"debug.getinfo", `debug.getinfo(1)`},
		{"require", `require("os")`},
		{"dofile", `dofile("/etc/passwd")`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ds, err := NewLuaDataSource(LuaDataSourceConfig{
				Name:   "sandbox",
				Script: "function fetch(input)\n  " + tt.call + "\n  return {data = \"{}\"}\nend\n",
			})
			if err != nil {
				t.Fatalf("NewLuaDataSource: %v", err)
			}

			_, err = ds.Fetch(context.Background(), aliceInput())
			if err == nil {
				t.Fatalf("expected %s to fail inside fetch, got nil error", tt.name)
			}
			if !strings.Contains(err.Error(), "script execution failed") {
				t.Errorf("error = %v, want script execution failure", err)
			}
		})
	}
}

func TestNewLuaDataSource_TopLevelStdlibUseRejected(t *testing.T) {
	_, err := NewLuaDataSource(LuaDataSourceConfig{
		Name: "sandbox",
		Script: `
local home = os.getenv("HOME")
function fetch(input) return nil end
`,
	})
	if err == nil {
		t.Fatal("expected construction to fail when top-level code uses os")
	}
}

func TestCacheableLuaDataSource_CacheKey_RunsSandboxed(t *testing.T) {
	ds, err := NewCacheableLuaDataSource(CacheableLuaDataSourceConfig{
		Name: "sandbox",
		Script: `
function fetch(input) return nil end
function fetch_cache_key(input)
  if os ~= nil or io ~= nil or debug ~= nil then
    error("stdlib exposed")
  end
  return {subject = {subject = "sandboxed"}}
end
`,
	})
	if err != nil {
		t.Fatalf("NewCacheableLuaDataSource: %v", err)
	}

	key, ok := ds.CacheKey(context.Background(), aliceInput())
	if !ok {
		t.Fatal("CacheKey returned ok=false")
	}
	// On script error CacheKey falls back to the full input ("alice").
	if key.Subject == nil || key.Subject.Subject != "sandboxed" {
		t.Errorf("cache key subject = %+v, want sandboxed", key.Subject)
	}
}

func TestLuaDataSource_MaxResponseBytes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`{"padding":"` + strings.Repeat("x", 64) + `"}`))
	}))
	defer server.Close()

	script := `
function fetch(input)
  local response, err = http.get("/data")
  if response == nil then
    error("fetch failed: " .. err)
  end
  return {data = response.body, content_type = "application/json"}
end
`

	t.Run("over limit fails with truncation error", func(t *testing.T) {
		ds, err := NewLuaDataSource(LuaDataSourceConfig{
			Name:             "limited",
			Script:           script,
			HTTP:             httpclient.LuaClient{Client: server.Client(), BaseURL: server.URL},
			MaxResponseBytes: 16,
		})
		if err != nil {
			t.Fatalf("NewLuaDataSource: %v", err)
		}
		_, err = ds.Fetch(context.Background(), aliceInput())
		if err == nil || !strings.Contains(err.Error(), luaservices.ErrResponseTooLarge.Error()) {
			t.Fatalf("err = %v, want %q", err, luaservices.ErrResponseTooLarge)
		}
	})

	t.Run("default limit allows small body", func(t *testing.T) {
		ds, err := NewLuaDataSource(LuaDataSourceConfig{
			Name:   "default",
			Script: script,
			HTTP:   httpclient.LuaClient{Client: server.Client(), BaseURL: server.URL},
		})
		if err != nil {
			t.Fatalf("NewLuaDataSource: %v", err)
		}
		result, err := ds.Fetch(context.Background(), aliceInput())
		if err != nil {
			t.Fatalf("Fetch: %v", err)
		}
		if result == nil || !strings.Contains(string(result.Data), "padding") {
			t.Errorf("result = %+v, want upstream body", result)
		}
	})
}

func TestNewLuaDataSource_NegativeMaxResponseBytesRejected(t *testing.T) {
	_, err := NewLuaDataSource(LuaDataSourceConfig{
		Name:             "bad",
		Script:           `function fetch(input) return nil end`,
		MaxResponseBytes: -1,
	})
	if err == nil {
		t.Fatal("expected error for negative MaxResponseBytes")
	}
}

func TestLuaDataSource_PathEscapeKeepsSubjectInOneSegment(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.EscapedPath()
		_, _ = w.Write([]byte(`{}`))
	}))
	defer server.Close()

	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name: "escape",
		Script: `
function fetch(input)
  local response = http.get("/users/" .. url.path_escape(input.subject.subject))
  return {data = response.body}
end
`,
		HTTP: httpclient.LuaClient{Client: server.Client(), BaseURL: server.URL},
	})
	if err != nil {
		t.Fatalf("NewLuaDataSource: %v", err)
	}

	tests := []struct {
		subject string
		want    string
	}{
		{"alice", "/users/alice"},
		{"..", "/users/%2E%2E"},
		{"../admin", "/users/..%2Fadmin"},
		{"x?role=admin#frag", "/users/x%3Frole=admin%23frag"},
	}
	for _, tt := range tests {
		t.Run(tt.subject, func(t *testing.T) {
			gotPath = ""
			_, err := ds.Fetch(context.Background(), &service.DataSourceInput{
				Subject: &trust.Result{Subject: tt.subject},
			})
			if err != nil {
				t.Fatalf("Fetch: %v", err)
			}
			if gotPath != tt.want {
				t.Errorf("request path = %q, want %q", gotPath, tt.want)
			}
		})
	}
}
