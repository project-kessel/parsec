package datasource

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/project-kessel/parsec/internal/httpclient"
	"github.com/project-kessel/parsec/internal/service"
	"github.com/project-kessel/parsec/internal/trust"
)

func TestLuaDataSource_HTTPBaseURL(t *testing.T) {
	var gotPath string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.String()
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer server.Close()

	ds, err := NewLuaDataSource(LuaDataSourceConfig{
		Name: "export-compliance",
		Script: `
function fetch(input)
	local response = http.get("/v1/compliance")
	if response == nil then
		return nil
	end
	return {data = response.body, content_type = "application/json"}
end
`,
		HTTP: httpclient.LuaClient{BaseURL: server.URL},
	})
	if err != nil {
		t.Fatalf("NewLuaDataSource: %v", err)
	}

	result, err := ds.Fetch(context.Background(), &service.DataSourceInput{
		Subject: &trust.Result{Subject: "alice"},
	})
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if result == nil {
		t.Fatal("Fetch returned nil result")
	}
	if gotPath != "/v1/compliance" {
		t.Errorf("request path = %q, want %q", gotPath, "/v1/compliance")
	}
}
