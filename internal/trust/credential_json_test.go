package trust

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestMarshalCredentialJSON_RoundTrip(t *testing.T) {
	tests := []struct {
		name       string
		credential Credential
		check      func(t *testing.T, got Credential)
	}{
		{
			name:       "bearer credential",
			credential: &BearerCredential{Token: "my-token"},
			check: func(t *testing.T, got Credential) {
				bearer, ok := got.(*BearerCredential)
				if !ok {
					t.Fatalf("expected *BearerCredential, got %T", got)
				}
				if bearer.Token != "my-token" {
					t.Fatalf("Token=%q, want my-token", bearer.Token)
				}
			},
		},
		{
			name: "jwt credential",
			credential: &JWTCredential{
				BearerCredential: BearerCredential{Token: "jwt-token"},
				Algorithm:        "RS256",
				KeyID:            "key-1",
				IssuerIdentity:   "https://issuer.example.com",
			},
			check: func(t *testing.T, got Credential) {
				jwt, ok := got.(*JWTCredential)
				if !ok {
					t.Fatalf("expected *JWTCredential, got %T", got)
				}
				if jwt.Token != "jwt-token" {
					t.Fatalf("Token=%q", jwt.Token)
				}
				if jwt.Algorithm != "RS256" {
					t.Fatalf("Algorithm=%q", jwt.Algorithm)
				}
				if jwt.KeyID != "key-1" {
					t.Fatalf("KeyID=%q", jwt.KeyID)
				}
				if jwt.IssuerIdentity != "https://issuer.example.com" {
					t.Fatalf("IssuerIdentity=%q", jwt.IssuerIdentity)
				}
			},
		},
		{
			name: "oidc credential",
			credential: &OIDCCredential{
				Token:          "oidc-token",
				IssuerIdentity: "https://idp.example.com",
				ClientID:       "client-123",
			},
			check: func(t *testing.T, got Credential) {
				oidc, ok := got.(*OIDCCredential)
				if !ok {
					t.Fatalf("expected *OIDCCredential, got %T", got)
				}
				if oidc.Token != "oidc-token" {
					t.Fatalf("Token=%q", oidc.Token)
				}
				if oidc.IssuerIdentity != "https://idp.example.com" {
					t.Fatalf("IssuerIdentity=%q", oidc.IssuerIdentity)
				}
				if oidc.ClientID != "client-123" {
					t.Fatalf("ClientID=%q", oidc.ClientID)
				}
			},
		},
		{
			name: "mtls credential",
			credential: &MTLSCredential{
				Certificate:         []byte{0x30, 0x82, 0x01},
				Chain:               [][]byte{{0x30, 0x82, 0x02}, {0x30, 0x82, 0x03}},
				PeerCertificateHash: "sha256:abc123",
				IssuerIdentity:      "ca.example.com",
			},
			check: func(t *testing.T, got Credential) {
				mtls, ok := got.(*MTLSCredential)
				if !ok {
					t.Fatalf("expected *MTLSCredential, got %T", got)
				}
				if string(mtls.Certificate) != string([]byte{0x30, 0x82, 0x01}) {
					t.Fatalf("Certificate mismatch")
				}
				if len(mtls.Chain) != 2 {
					t.Fatalf("Chain len=%d, want 2", len(mtls.Chain))
				}
				if mtls.PeerCertificateHash != "sha256:abc123" {
					t.Fatalf("PeerCertificateHash=%q", mtls.PeerCertificateHash)
				}
				if mtls.IssuerIdentity != "ca.example.com" {
					t.Fatalf("IssuerIdentity=%q", mtls.IssuerIdentity)
				}
			},
		},
		{
			name: "json credential",
			credential: &JSONCredential{
				RawJSON: []byte(`{"subject":"user@example.com"}`),
			},
			check: func(t *testing.T, got Credential) {
				jc, ok := got.(*JSONCredential)
				if !ok {
					t.Fatalf("expected *JSONCredential, got %T", got)
				}
				if string(jc.RawJSON) != `{"subject":"user@example.com"}` {
					t.Fatalf("RawJSON=%q", string(jc.RawJSON))
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, err := MarshalCredentialJSON(tt.credential)
			if err != nil {
				t.Fatalf("MarshalCredentialJSON: %v", err)
			}

			// Verify type field is present in JSON
			var envelope struct {
				Type CredentialType `json:"type"`
			}
			if err := json.Unmarshal(data, &envelope); err != nil {
				t.Fatalf("unmarshal envelope: %v", err)
			}
			if envelope.Type != tt.credential.Type() {
				t.Fatalf("JSON type=%q, want %q", envelope.Type, tt.credential.Type())
			}

			got, err := UnmarshalCredentialJSON(data)
			if err != nil {
				t.Fatalf("UnmarshalCredentialJSON: %v", err)
			}
			if got.Type() != tt.credential.Type() {
				t.Fatalf("roundtrip Type()=%q, want %q", got.Type(), tt.credential.Type())
			}
			tt.check(t, got)
		})
	}
}

func TestMarshalCredentialJSON_OmitsEmptyFields(t *testing.T) {
	data, err := MarshalCredentialJSON(&JWTCredential{
		BearerCredential: BearerCredential{Token: "tok"},
	})
	if err != nil {
		t.Fatalf("MarshalCredentialJSON: %v", err)
	}

	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	if _, ok := fields["algorithm"]; ok {
		t.Error("expected algorithm to be omitted when empty")
	}
	if _, ok := fields["key_id"]; ok {
		t.Error("expected key_id to be omitted when empty")
	}
}

func TestUnmarshalCredentialJSON_Errors(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		wantErr string
	}{
		{
			name:    "invalid json",
			input:   `{not json`,
			wantErr: "failed to read credential type",
		},
		{
			name:    "missing type",
			input:   `{"token":"abc"}`,
			wantErr: "unsupported credential type",
		},
		{
			name:    "unknown type",
			input:   `{"type":"unknown","token":"abc"}`,
			wantErr: "unsupported credential type",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := UnmarshalCredentialJSON([]byte(tt.input))
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("err=%q, want containing %q", err.Error(), tt.wantErr)
			}
		})
	}
}

func TestMarshalCredentialJSON_NilCredential(t *testing.T) {
	_, err := MarshalCredentialJSON(nil)
	if err == nil {
		t.Fatal("expected error for nil credential")
	}
}

func TestValidatorInput_JSONRoundTrip(t *testing.T) {
	input := ValidatorInput{
		Credential: &JWTCredential{
			BearerCredential: BearerCredential{Token: "test-token"},
			Algorithm:        "RS256",
			KeyID:            "key-1",
			IssuerIdentity:   "https://issuer.example.com",
		},
	}

	data, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}

	var got ValidatorInput
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}

	jwt, ok := got.Credential.(*JWTCredential)
	if !ok {
		t.Fatalf("expected *JWTCredential, got %T", got.Credential)
	}
	if jwt.Token != "test-token" || jwt.Algorithm != "RS256" {
		t.Fatalf("roundtrip mismatch: %+v", jwt)
	}
}
