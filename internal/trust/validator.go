package trust

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/project-kessel/parsec/internal/claims"
)

// Common validation errors
var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
)

// Validator validates external credentials and returns claims about the authenticated subject
type Validator interface {
	// Validate validates a credential and returns the validation result
	// Returns an error if the credential is invalid or validation fails
	Validate(ctx context.Context, credential Credential) (*Result, error)

	// CredentialTypes returns the set of credential types this validator can handle
	// A validator may support multiple types (e.g., JWT validator can handle Bearer or JWT)
	CredentialTypes() []CredentialType
}

// CacheableValidator is an optional interface for validators whose successful
// validation results can be cached. The cache TTL is configured on the
// caching wrapper, not on the validator itself.
type CacheableValidator interface {
	// CacheKey returns a masked validator input containing only the fields that
	// affect the validation result. For distributed caches, the returned input
	// must be sufficient to reconstruct a Credential and call Validate on a
	// cache miss.
	CacheKey(credential Credential) (ValidatorInput, error)
}

// Result contains the validated information about the subject.
// All fields are exported and JSON-serializable.
//
// Callers must treat Result and its reference-type fields (Claims, Audience)
// as read-only. Results may be shared across goroutines and cached; mutating
// a returned Result corrupts shared state.
type Result struct {
	// Subject is the unique identifier of the authenticated subject
	Subject string `json:"subject"`

	// Issuer is the issuer of the credential (e.g., IdP URL)
	Issuer string `json:"issuer"`

	// TrustDomain is the trust domain the credential belongs to.
	// This namespaces the subject identifier and claims.
	// An issuer is often 1:1 with a trust domain but not always.
	TrustDomain string `json:"trust_domain"`

	// Claims are additional claims from the credential
	Claims claims.Claims `json:"claims,omitempty"`

	// ExpiresAt is when the validated credential expires
	ExpiresAt time.Time `json:"expires_at"`

	// IssuedAt is when the credential was issued
	IssuedAt time.Time `json:"issued_at"`

	// Audience is the intended audience of the credential
	Audience []string `json:"audience,omitempty"`

	// Scope is the OAuth2 scope if applicable
	Scope string `json:"scope,omitempty"`
}

// AnonymousResult returns a Result representing an anonymous/unauthenticated actor
// This is used when no actor credentials are present or provided
func AnonymousResult() *Result {
	return &Result{}
}

// CredentialType indicates the type of credential
type CredentialType string

const (
	CredentialTypeBearer CredentialType = "bearer"
	CredentialTypeJWT    CredentialType = "jwt"
	CredentialTypeOIDC   CredentialType = "oidc"
	CredentialTypeMTLS   CredentialType = "mtls"
	CredentialTypeOAuth2 CredentialType = "oauth2"
	CredentialTypeJSON   CredentialType = "json"
)

// Credential is the interface for all credential types
// Credentials encapsulate only the material needed for validation
type Credential interface {
	// Type returns the credential type
	Type() CredentialType
}

// BearerCredential represents a simple bearer token
// For opaque bearer tokens, the trust store determines which validator to use
// based on its configuration (e.g., default validator, token introspection, etc.)
type BearerCredential struct {
	Token string `json:"token"`
}

func (c *BearerCredential) Type() CredentialType {
	return CredentialTypeBearer
}

// JWTCredential represents a JWT token with parsed header and claims
type JWTCredential struct {
	BearerCredential
	Algorithm      string `json:"algorithm,omitempty"`
	KeyID          string `json:"key_id,omitempty"`
	IssuerIdentity string `json:"issuer_identity,omitempty"`
}

func (c *JWTCredential) Type() CredentialType {
	return CredentialTypeJWT
}

// OIDCCredential represents an OIDC token with additional context
type OIDCCredential struct {
	Token          string `json:"token"`
	IssuerIdentity string `json:"issuer_identity,omitempty"`
	ClientID       string `json:"client_id,omitempty"`
}

func (c *OIDCCredential) Type() CredentialType {
	return CredentialTypeOIDC
}

// MTLSCredential represents client certificate authentication
type MTLSCredential struct {
	// TODO: use strongly typed fields that go gives us rather than raw bytes

	// Certificate is the client certificate (DER encoded)
	Certificate []byte `json:"certificate,omitempty"`

	// Chain is the certificate chain (DER encoded)
	Chain [][]byte `json:"chain,omitempty"`

	// PeerCertificateHash for validation
	PeerCertificateHash string `json:"peer_certificate_hash,omitempty"`

	// IssuerIdentity identifies the CA/trust domain
	IssuerIdentity string `json:"issuer_identity,omitempty"`
}

func (c *MTLSCredential) Type() CredentialType {
	return CredentialTypeMTLS
}

// JSONCredential represents an unsigned JSON credential with a well-defined structure
// This is used for pre-validated or self-asserted credentials where the structure
// follows the Result format
type JSONCredential struct {
	// RawJSON is the raw JSON bytes
	RawJSON []byte
}

func (c *JSONCredential) Type() CredentialType {
	return CredentialTypeJSON
}

func (c *JSONCredential) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		RawJSON string `json:"raw_json"`
	}{RawJSON: string(c.RawJSON)})
}

func (c *JSONCredential) UnmarshalJSON(data []byte) error {
	var raw struct {
		RawJSON string `json:"raw_json"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	c.RawJSON = []byte(raw.RawJSON)
	return nil
}

// MarshalCredentialJSON serializes a [Credential] to JSON with a "type"
// discriminator field. The concrete credential struct must have json tags.
func MarshalCredentialJSON(c Credential) ([]byte, error) {
	if c == nil {
		return nil, fmt.Errorf("credential cannot be nil")
	}
	raw, err := json.Marshal(c)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal credential: %w", err)
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("credential must marshal to a JSON object: %w", err)
	}
	typeBytes, _ := json.Marshal(c.Type())
	obj["type"] = typeBytes
	return json.Marshal(obj)
}

// UnmarshalCredentialJSON deserializes a [Credential] from JSON using the
// "type" discriminator field to select the concrete type.
func UnmarshalCredentialJSON(data []byte) (Credential, error) {
	var envelope struct {
		Type CredentialType `json:"type"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, fmt.Errorf("failed to read credential type: %w", err)
	}
	switch envelope.Type {
	case CredentialTypeBearer:
		var c BearerCredential
		return &c, json.Unmarshal(data, &c)
	case CredentialTypeJWT:
		var c JWTCredential
		return &c, json.Unmarshal(data, &c)
	case CredentialTypeOIDC:
		var c OIDCCredential
		return &c, json.Unmarshal(data, &c)
	case CredentialTypeMTLS:
		var c MTLSCredential
		return &c, json.Unmarshal(data, &c)
	case CredentialTypeJSON:
		var c JSONCredential
		return &c, json.Unmarshal(data, &c)
	default:
		return nil, fmt.Errorf("unsupported credential type: %s", envelope.Type)
	}
}
