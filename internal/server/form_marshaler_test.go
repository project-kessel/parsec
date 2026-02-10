package server

import (
	"bytes"
	"testing"

	parsecv1 "github.com/project-kessel/parsec/api/gen/parsec/v1"
)

func TestFormMarshaler_Unmarshal(t *testing.T) {
	marshaler := NewFormMarshaler()

	tests := []struct {
		name    string
		data    string
		want    *parsecv1.ExchangeRequest
		wantErr bool
	}{
		{
			name: "basic token exchange request",
			data: "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" +
				"&subject_token=eyJhbGc.payload.signature" +
				"&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt" +
				"&audience=https%3A%2F%2Fexample.com",
			want: &parsecv1.ExchangeRequest{
				GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
				SubjectToken:     "eyJhbGc.payload.signature",
				SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
				Audience:         "https://example.com",
			},
			wantErr: false,
		},
		{
			name: "with optional fields",
			data: "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" +
				"&subject_token=token123" +
				"&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt" +
				"&resource=https%3A%2F%2Fapi.example.com" +
				"&scope=read%20write",
			want: &parsecv1.ExchangeRequest{
				GrantType:        "urn:ietf:params:oauth:grant-type:token-exchange",
				SubjectToken:     "token123",
				SubjectTokenType: "urn:ietf:params:oauth:token-type:jwt",
				Resource:         "https://api.example.com",
				Scope:            "read write",
			},
			wantErr: false,
		},
		{
			name:    "invalid form data",
			data:    "%ZZ%invalid",
			want:    &parsecv1.ExchangeRequest{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := &parsecv1.ExchangeRequest{}
			err := marshaler.Unmarshal([]byte(tt.data), got)

			if (err != nil) != tt.wantErr {
				t.Errorf("Unmarshal() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			if got.GrantType != tt.want.GrantType {
				t.Errorf("GrantType = %v, want %v", got.GrantType, tt.want.GrantType)
			}
			if got.SubjectToken != tt.want.SubjectToken {
				t.Errorf("SubjectToken = %v, want %v", got.SubjectToken, tt.want.SubjectToken)
			}
			if got.SubjectTokenType != tt.want.SubjectTokenType {
				t.Errorf("SubjectTokenType = %v, want %v", got.SubjectTokenType, tt.want.SubjectTokenType)
			}
			if got.Audience != tt.want.Audience {
				t.Errorf("Audience = %v, want %v", got.Audience, tt.want.Audience)
			}
			if got.Resource != tt.want.Resource {
				t.Errorf("Resource = %v, want %v", got.Resource, tt.want.Resource)
			}
			if got.Scope != tt.want.Scope {
				t.Errorf("Scope = %v, want %v", got.Scope, tt.want.Scope)
			}
		})
	}
}

func TestFormMarshaler_Decoder(t *testing.T) {
	marshaler := NewFormMarshaler()

	formData := "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Atoken-exchange" +
		"&subject_token=test_token" +
		"&subject_token_type=urn%3Aietf%3Aparams%3Aoauth%3Atoken-type%3Ajwt"

	reader := bytes.NewBufferString(formData)
	decoder := marshaler.NewDecoder(reader)

	req := &parsecv1.ExchangeRequest{}
	err := decoder.Decode(req)
	if err != nil {
		t.Fatalf("Decode() error = %v", err)
	}

	if req.GrantType != "urn:ietf:params:oauth:grant-type:token-exchange" {
		t.Errorf("GrantType = %v, want %v", req.GrantType, "urn:ietf:params:oauth:grant-type:token-exchange")
	}
	if req.SubjectToken != "test_token" {
		t.Errorf("SubjectToken = %v, want %v", req.SubjectToken, "test_token")
	}
}

func TestFormMarshaler_ContentType(t *testing.T) {
	marshaler := NewFormMarshaler()
	contentType := marshaler.ContentType(nil)

	want := "application/x-www-form-urlencoded"
	if contentType != want {
		t.Errorf("ContentType() = %v, want %v", contentType, want)
	}
}
