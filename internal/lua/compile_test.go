package lua

import (
	"strings"
	"testing"

	golua "github.com/yuin/gopher-lua"
)

func TestCompileScript(t *testing.T) {
	proto, err := CompileScript(`function hello() return "hi" end`, "test")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proto == nil {
		t.Fatal("expected non-nil proto")
	}
}

func TestCompileScript_ParseError(t *testing.T) {
	_, err := CompileScript(`function hello(`, "bad-script")
	if err == nil {
		t.Fatal("expected error for invalid syntax")
	}
	if !strings.Contains(err.Error(), "failed to parse script") {
		t.Fatalf("err=%q, want containing 'failed to parse script'", err)
	}
}

func TestValidateFunction(t *testing.T) {
	proto, err := CompileScript(`function validate(input) return nil end`, "test")
	if err != nil {
		t.Fatalf("CompileScript: %v", err)
	}

	if err := ValidateFunction(proto, "validate"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestValidateFunction_Missing(t *testing.T) {
	proto, err := CompileScript(`function other() return nil end`, "test")
	if err != nil {
		t.Fatalf("CompileScript: %v", err)
	}

	err = ValidateFunction(proto, "validate")
	if err == nil {
		t.Fatal("expected error for missing function")
	}
	if !strings.Contains(err.Error(), "script must define a 'validate' function") {
		t.Fatalf("err=%q, want containing script must define", err)
	}
}

func TestValidateFunction_NotAFunction(t *testing.T) {
	proto, err := CompileScript(`validate = "not a function"`, "test")
	if err != nil {
		t.Fatalf("CompileScript: %v", err)
	}

	err = ValidateFunction(proto, "validate")
	if err == nil {
		t.Fatal("expected error when global is not a function")
	}
	if !strings.Contains(err.Error(), "script must define a 'validate' function") {
		t.Fatalf("err=%q, want containing script must define", err)
	}
}

func TestLoadProto(t *testing.T) {
	proto, err := CompileScript(`greeting = "hello"`, "test")
	if err != nil {
		t.Fatalf("CompileScript: %v", err)
	}

	L := golua.NewState()
	defer L.Close()

	if err := LoadProto(L, proto); err != nil {
		t.Fatalf("LoadProto: %v", err)
	}

	val := L.GetGlobal("greeting")
	if val.String() != "hello" {
		t.Fatalf("greeting=%q, want hello", val.String())
	}
}
