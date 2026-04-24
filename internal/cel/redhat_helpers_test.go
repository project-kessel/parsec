package cel

import (
	"testing"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
)

func TestIsConsoleApiToken_CEL(t *testing.T) {
	env, err := cel.NewEnv(
		RedHatHelpersLibrary(),
		cel.Variable("claims", cel.DynType),
	)
	if err != nil {
		t.Fatalf("NewEnv: %v", err)
	}

	ast, iss := env.Compile(`isConsoleApiToken(claims)`)
	if iss.Err() != nil {
		t.Fatalf("Compile: %v", iss.Err())
	}
	prg, err := env.Program(ast)
	if err != nil {
		t.Fatalf("Program: %v", err)
	}

	tests := []struct {
		name   string
		claims map[string]any
		want   bool
	}{
		{
			name:   "false when scope is api.consoletools not api.console",
			claims: map[string]any{"scope": "openid api.consoletools"},
			want:   false,
		},
		{
			name:   "false when scope only has substring not.api.console",
			claims: map[string]any{"scope": "openid not.api.console"},
			want:   false,
		},
		{
			name:   "false when scope claim missing",
			claims: map[string]any{},
			want:   false,
		},
		{
			name:   "true when api.console is a full token",
			claims: map[string]any{"scope": "openid api.console profile"},
			want:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, _, err := prg.Eval(map[string]any{"claims": tt.claims})
			if err != nil {
				t.Fatalf("Eval: %v", err)
			}
			got, ok := out.Value().(bool)
			if !ok {
				t.Fatalf("got %v (%T), want bool", out.Value(), out.Value())
			}
			if got != tt.want {
				t.Fatalf("isConsoleApiToken(...) = %v, want %v", got, tt.want)
			}
			if out.Type() != types.BoolType {
				t.Fatalf("result type = %v, want bool", out.Type())
			}
		})
	}
}
