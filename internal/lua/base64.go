package lua

import (
	"encoding/base64"
	"fmt"

	lua "github.com/yuin/gopher-lua"
)

// Base64Service provides base64 encoding/decoding to Lua scripts.
type Base64Service struct{}

// NewBase64Service creates a new base64 service.
func NewBase64Service() *Base64Service {
	return &Base64Service{}
}

// Register adds the base64 service to the Lua state.
// Usage in Lua:
//
//	local encoded = base64.encode("hello")
//	local decoded, err = base64.decode(encoded)
func (s *Base64Service) Register(L *lua.LState) {
	mod := L.NewTable()
	L.SetField(mod, "encode", L.NewFunction(s.luaBase64Encode))
	L.SetField(mod, "decode", L.NewFunction(s.luaBase64Decode))
	L.SetGlobal("base64", mod)
}

// luaBase64Encode encodes a string with standard base64.
// Args: data (string)
// Returns: encoded_string or (nil, error)
func (s *Base64Service) luaBase64Encode(L *lua.LState) int {
	data := L.CheckString(1)
	L.Push(lua.LString(base64.StdEncoding.EncodeToString([]byte(data))))
	return 1
}

// luaBase64Decode decodes a standard base64 string.
// Args: encoded (string)
// Returns: decoded_string or (nil, error)
func (s *Base64Service) luaBase64Decode(L *lua.LState) int {
	encoded := L.CheckString(1)
	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		L.Push(lua.LNil)
		L.Push(lua.LString(fmt.Sprintf("failed to decode base64: %v", err)))
		return 2
	}
	L.Push(lua.LString(string(decoded)))
	return 1
}
