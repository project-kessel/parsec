package trust

import (
	"context"
	"testing"
)

func TestLuaValidator_StdlibEscapesFail(t *testing.T) {
	tests := []struct {
		name string
		call string
	}{
		{"os.execute", `os.execute("id")`},
		{"os.getenv", `os.getenv("HOME")`},
		{"io.open", `io.open("/etc/passwd", "r")`},
		{"debug.getinfo", `debug.getinfo(1)`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			script := "function validate(input)\n  " + tt.call + "\n  return nil\nend\n"
			v, err := NewLuaValidator("sandbox", script, []CredentialType{CredentialTypeBearer})
			if err != nil {
				t.Fatalf("NewLuaValidator: %v", err)
			}
			if _, err := v.Validate(context.Background(), &BearerCredential{Token: "tok"}); err == nil {
				t.Fatalf("expected %s to fail inside validate, got nil error", tt.name)
			}
		})
	}
}

func TestNewLuaValidator_TopLevelStdlibUseRejected(t *testing.T) {
	script := `
os.execute("id")
function validate(input) return nil end
`
	if _, err := NewLuaValidator("sandbox", script, []CredentialType{CredentialTypeBearer}); err == nil {
		t.Fatal("expected construction to fail when top-level code uses os")
	}
}
