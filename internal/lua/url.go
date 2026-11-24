package lua

import (
	"net/url"

	lua "github.com/yuin/gopher-lua"
)

// URLService provides URL encoding/decoding functionality to Lua scripts
type URLService struct{}

// NewURLService creates a new URL service
func NewURLService() *URLService {
	return &URLService{}
}

// Register adds the URL service to the Lua state
// Usage in Lua:
//
//	local encoded = url.encode("/C=US/ST=North Carolina")
//	local path = "/users/" .. url.path_escape(input.subject.subject)
func (s *URLService) Register(L *lua.LState) {
	mod := L.NewTable()
	L.SetField(mod, "encode", L.NewFunction(s.luaURLEncode))
	L.SetField(mod, "path_escape", L.NewFunction(s.luaPathEscape))
	L.SetGlobal("url", mod)
}

func (s *URLService) luaURLEncode(L *lua.LState) int {
	value := L.CheckString(1)
	L.Push(lua.LString(url.PathEscape(value)))
	return 1
}

func (s *URLService) luaPathEscape(L *lua.LState) int {
	value := L.CheckString(1)
	L.Push(lua.LString(PathSegmentEscape(value)))
	return 1
}

// PathSegmentEscape escapes value so it is safe to place in a single URL path
// segment. It applies [url.PathEscape], which encodes "/", "?", "#" and other
// reserved characters, and also encodes the dot segments "." and "..". Without
// that, an untrusted value such as ".." would be removed by URL resolution and
// let the request climb to a parent path (CWE-22).
func PathSegmentEscape(value string) string {
	switch value {
	case ".":
		return "%2E"
	case "..":
		return "%2E%2E"
	default:
		return url.PathEscape(value)
	}
}
