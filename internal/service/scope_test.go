package service

import "testing"

func TestNewOAuthScope_rejectsEmptyAndWhitespace(t *testing.T) {
	tests := []string{"", " ", "\t", "  \n  "}
	for _, raw := range tests {
		if _, ok := NewOAuthScope(raw); ok {
			t.Errorf("NewOAuthScope(%q) = ok, want false", raw)
		}
	}

	scope, ok := NewOAuthScope("  read write  ")
	if !ok {
		t.Fatal("expected valid scope")
	}
	if scope.String() != "read write" {
		t.Errorf("String() = %q, want %q", scope.String(), "read write")
	}
}

func TestOAuthScope_zeroValueIsOmit(t *testing.T) {
	var scope OAuthScope
	if scope.IsPresent() {
		t.Error("zero OAuthScope should not be present")
	}
	if scope.String() != "" {
		t.Errorf("String() = %q, want empty", scope.String())
	}
	if OmitScope().IsPresent() {
		t.Error("OmitScope() should not be present")
	}
}
