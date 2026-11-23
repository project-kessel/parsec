package lua

import (
	lua "github.com/yuin/gopher-lua"
)

// sandboxLibs lists the only Lua standard libraries opened in a sandboxed
// state. io, os, debug, package, channel, and coroutine are deliberately
// excluded: scripts are configuration supplied, so they must not be able to
// execute commands, touch the filesystem, read environment variables (which
// may hold credentials), or introspect the VM.
var sandboxLibs = []struct {
	name string
	open lua.LGFunction
}{
	{lua.BaseLibName, lua.OpenBase},
	{lua.TabLibName, lua.OpenTable},
	{lua.StringLibName, lua.OpenString},
	{lua.MathLibName, lua.OpenMath},
}

// sandboxRemovedGlobals are functions registered by the base library that
// reach outside the sandbox. dofile and loadfile read from the filesystem.
// require and module belong to the package library, which is not opened.
// _printregs dumps VM internals.
var sandboxRemovedGlobals = []string{
	"dofile",
	"loadfile",
	"require",
	"module",
	"_printregs",
}

// NewSandboxedState returns a Lua state that has only the base, table,
// string, and math libraries. The caller owns the state and must Close it.
//
// Every LState that runs configuration-supplied scripts must be created
// through this function, including temporary states used for validation,
// because loading a script executes its top-level chunk.
func NewSandboxedState() *lua.LState {
	L := lua.NewState(lua.Options{SkipOpenLibs: true})
	for _, lib := range sandboxLibs {
		L.Push(L.NewFunction(lib.open))
		L.Push(lua.LString(lib.name))
		L.Call(1, 0)
	}
	for _, name := range sandboxRemovedGlobals {
		L.SetGlobal(name, lua.LNil)
	}
	return L
}
