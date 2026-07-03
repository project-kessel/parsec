package lua

import (
	"fmt"
	"strings"

	lua "github.com/yuin/gopher-lua"
	"github.com/yuin/gopher-lua/parse"
)

// CompileScript parses and compiles a Lua script to bytecode.
// The returned [lua.FunctionProto] is immutable and safe to share
// across goroutines and LState instances.
func CompileScript(source string, name string) (*lua.FunctionProto, error) {
	chunk, err := parse.Parse(strings.NewReader(source), name)
	if err != nil {
		return nil, fmt.Errorf("failed to parse script: %w", err)
	}
	proto, err := lua.Compile(chunk, name)
	if err != nil {
		return nil, fmt.Errorf("failed to compile script: %w", err)
	}
	return proto, nil
}

// ValidateFunction loads a pre-compiled script into a temporary LState
// and verifies that executing it defines a global function with the given name.
func ValidateFunction(proto *lua.FunctionProto, functionName string) error {
	L := lua.NewState()
	defer L.Close()

	if err := LoadProto(L, proto); err != nil {
		return fmt.Errorf("failed to load script: %w", err)
	}

	fn := L.GetGlobal(functionName)
	if fn.Type() != lua.LTFunction {
		return fmt.Errorf("script must define a '%s' function", functionName)
	}

	return nil
}

// LoadProto loads a pre-compiled [lua.FunctionProto] into an LState and
// executes its top-level chunk, which typically defines global functions.
func LoadProto(L *lua.LState, proto *lua.FunctionProto) error {
	fn := L.NewFunctionFromProto(proto)
	L.Push(fn)
	return L.PCall(0, lua.MultRet, nil)
}
