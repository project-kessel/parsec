package httpclient

import (
	"fmt"
	"net/http"
)

// LuaClient bundles an [*http.Client] with an optional base URL for Lua scripts.
// Relative paths in http.get/post/request resolve against BaseURL; absolute URLs
// are unchanged. JWT validators and other non-Lua callers use [Registry.Get] only.
type LuaClient struct {
	Client  *http.Client
	BaseURL string
}

// HTTPClient returns the underlying client, or [http.DefaultClient] when Client is nil.
func (c LuaClient) HTTPClient() *http.Client {
	if c.Client == nil {
		return http.DefaultClient
	}
	return c.Client
}

// GetLua returns a named client and its optional Lua base URL.
func (r *Registry) GetLua(name ClientName) (LuaClient, error) {
	rc, ok := r.clients[name]
	if !ok {
		return LuaClient{}, fmt.Errorf("httpclient: client %q not found", name)
	}
	return LuaClient{Client: rc.client, BaseURL: rc.baseURL}, nil
}

// BuildLua creates an anonymous client from spec and returns it with its base URL.
func (r *Registry) BuildLua(spec ClientSpec) (LuaClient, error) {
	client, err := r.build("", spec)
	if err != nil {
		return LuaClient{}, err
	}
	return LuaClient{Client: client, BaseURL: spec.BaseURL}, nil
}
