package lua

import (
	"strings"
	"testing"

	lua "github.com/yuin/gopher-lua"
)

func TestNewSandboxedState_AllowedLibrariesWork(t *testing.T) {
	L := NewSandboxedState()
	defer L.Close()

	script := `
		local t = {}
		table.insert(t, string.upper("a"))
		table.insert(t, tostring(math.floor(2.7)))
		for _, v in ipairs({"x"}) do table.insert(t, v) end
		for k, _ in pairs({y = true}) do table.insert(t, k) end
		local ok = pcall(function() error("boom") end)
		table.insert(t, tostring(ok))
		local fn = loadstring("return 40 + 2")
		table.insert(t, tostring(fn()))
		result = table.concat(t, ",")
	`
	if err := L.DoString(script); err != nil {
		t.Fatalf("DoString: %v", err)
	}
	if got, want := L.GetGlobal("result").String(), "A,2,x,y,false,42"; got != want {
		t.Errorf("result = %q, want %q", got, want)
	}
}

func TestNewSandboxedState_DangerousGlobalsAreNil(t *testing.T) {
	names := []string{
		"os", "io", "debug", "package", "coroutine", "channel",
		"dofile", "loadfile", "require", "module", "_printregs",
	}

	L := NewSandboxedState()
	defer L.Close()

	for _, name := range names {
		if v := L.GetGlobal(name); v != lua.LNil {
			t.Errorf("global %q = %s (%s), want nil", name, v, v.Type())
		}
	}
}

func TestNewSandboxedState_DangerousCallsFail(t *testing.T) {
	tests := []struct {
		name   string
		script string
	}{
		{"os.execute", `os.execute("id")`},
		{"os.getenv", `return os.getenv("HOME")`},
		{"os.remove", `os.remove("/tmp/x")`},
		{"io.open", `io.open("/etc/passwd", "r")`},
		{"io.popen", `io.popen("id")`},
		{"debug.getinfo", `debug.getinfo(1)`},
		{"dofile", `dofile("/etc/passwd")`},
		{"loadfile", `loadfile("/etc/passwd")`},
		{"require", `require("os")`},
		{"string.dump", `string.dump(function() end)`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			L := NewSandboxedState()
			defer L.Close()

			if err := L.DoString(tt.script); err == nil {
				t.Fatalf("expected %s to fail in sandbox, got nil error", tt.name)
			}
		})
	}
}

func TestNewSandboxedState_GlobalsTableDoesNotExposeLibraries(t *testing.T) {
	L := NewSandboxedState()
	defer L.Close()

	// Indirect lookups through _G or getfenv must not reach removed libraries.
	script := `result = tostring(_G["os"]) .. "," .. tostring(_G["io"]) .. "," .. tostring(getfenv(0)["debug"])`
	if err := L.DoString(script); err != nil {
		t.Fatalf("DoString: %v", err)
	}
	if got, want := L.GetGlobal("result").String(), "nil,nil,nil"; got != want {
		t.Errorf("result = %q, want %q", got, want)
	}
}

func TestValidateFunction_TopLevelCodeRunsSandboxed(t *testing.T) {
	// Loading a script runs its top-level chunk, so validation at startup must
	// not give that chunk access to os or io.
	proto, err := CompileScript(`
os.execute("touch /tmp/parsec-sandbox-escape")
function fetch(input) return nil end
`, "escape")
	if err != nil {
		t.Fatalf("CompileScript: %v", err)
	}

	err = ValidateFunction(proto, "fetch")
	if err == nil {
		t.Fatal("expected ValidateFunction to fail when top-level code uses os")
	}
	if !strings.Contains(err.Error(), "failed to load script") {
		t.Errorf("error = %v, want it to mention failed to load script", err)
	}
}
