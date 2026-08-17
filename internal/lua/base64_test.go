package lua

import (
	"testing"

	lua "github.com/yuin/gopher-lua"
)

func TestBase64Service_Encode(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	NewBase64Service().Register(L)

	cases := []struct {
		name string
		in   string
		want string
	}{
		{name: "empty", in: "", want: ""},
		{name: "hello", in: "hello", want: "aGVsbG8="},
		{name: "json", in: `{"identity":{}}`, want: "eyJpZGVudGl0eSI6e319"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := L.DoString(`return base64.encode(` + luaStringLiteral(tc.in) + `)`); err != nil {
				t.Fatalf("DoString: %v", err)
			}
			got := L.Get(-1).String()
			L.Pop(1)
			if got != tc.want {
				t.Errorf("encode(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestBase64Service_Decode(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	NewBase64Service().Register(L)

	if err := L.DoString(`return base64.decode("aGVsbG8=")`); err != nil {
		t.Fatalf("DoString: %v", err)
	}
	got := L.Get(-1).String()
	L.Pop(1)
	if got != "hello" {
		t.Errorf("decode = %q, want hello", got)
	}
}

func TestBase64Service_DecodeError(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	NewBase64Service().Register(L)

	if err := L.DoString(`
		local v, err = base64.decode("!!!not-base64!!!")
		if v ~= nil then error("expected nil") end
		if err == nil or err == "" then error("expected error") end
		return err
	`); err != nil {
		t.Fatalf("DoString: %v", err)
	}
}

func TestBase64Service_RoundTrip(t *testing.T) {
	L := lua.NewState()
	defer L.Close()
	NewBase64Service().Register(L)

	if err := L.DoString(`
		local original = '{"identity":{"org_id":"org-1"}}'
		local encoded = base64.encode(original)
		local decoded, err = base64.decode(encoded)
		if err ~= nil then error(err) end
		return decoded == original
	`); err != nil {
		t.Fatalf("DoString: %v", err)
	}
	if L.Get(-1).Type() != lua.LTBool || !lua.LVAsBool(L.Get(-1)) {
		t.Fatal("expected round-trip equality")
	}
}

func luaStringLiteral(s string) string {
	// Escape for Lua long-bracket-free double-quoted string.
	out := `"`
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '\\', '"':
			out += `\` + string(c)
		case '\n':
			out += `\n`
		case '\r':
			out += `\r`
		case '\t':
			out += `\t`
		default:
			out += string(c)
		}
	}
	return out + `"`
}
