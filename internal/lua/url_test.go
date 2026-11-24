package lua

import (
	"testing"

	lua "github.com/yuin/gopher-lua"
)

func TestURLService_Encode(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			name:  "plain string",
			input: "hello",
			want:  "hello",
		},
		{
			name:  "spaces",
			input: "/C=US/ST=North Carolina",
			want:  "%2FC=US%2FST=North%20Carolina",
		},
		{
			name:  "special characters",
			input: "/C=US/ST=North Carolina/O=Red Hat, Inc./OU=Red Hat Network/CN=Red Hat Candlepin Authority/emailAddress=ca-support@redhat.com",
			want:  "%2FC=US%2FST=North%20Carolina%2FO=Red%20Hat%2C%20Inc.%2FOU=Red%20Hat%20Network%2FCN=Red%20Hat%20Candlepin%20Authority%2FemailAddress=ca-support@redhat.com",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			L := lua.NewState()
			defer L.Close()

			svc := NewURLService()
			svc.Register(L)

			err := L.DoString(`result = url.encode("` + tt.input + `")`)
			if err != nil {
				t.Fatalf("DoString() error: %v", err)
			}

			got := L.GetGlobal("result").String()
			if got != tt.want {
				t.Errorf("url.encode(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestURLService_PathEscape(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{"plain", "alice", "alice"},
		{"slash", "a/b", "a%2Fb"},
		{"traversal prefix", "../admin", "..%2Fadmin"},
		{"query and fragment", "x?y=1#z", "x%3Fy=1%23z"},
		{"space", "a b", "a%20b"},
		{"single dot segment", ".", "%2E"},
		{"double dot segment", "..", "%2E%2E"},
		{"dots inside value", "a..b", "a..b"},
		{"empty", "", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			L := lua.NewState()
			defer L.Close()
			NewURLService().Register(L)

			L.SetGlobal("input", lua.LString(tt.input))
			if err := L.DoString(`result = url.path_escape(input)`); err != nil {
				t.Fatalf("DoString() error: %v", err)
			}
			if got := L.GetGlobal("result").String(); got != tt.want {
				t.Errorf("url.path_escape(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}
