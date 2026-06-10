package trust

import (
	"context"
	"errors"
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

// Result contains the validated information about the subject
// All fields are exported and JSON-serializable
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
	Token string
}

func (c *BearerCredential) Type() CredentialType {
	return CredentialTypeBearer
}

// JWTCredential represents a JWT token with parsed header and claims
type JWTCredential struct {
	BearerCredential
	Algorithm      string
	KeyID          string
	IssuerIdentity string // Parsed from JWT "iss" claim
}

func (c *JWTCredential) Type() CredentialType {
	return CredentialTypeJWT
}

// OIDCCredential represents an OIDC token with additional context
type OIDCCredential struct {
	Token          string
	IssuerIdentity string // Parsed from JWT "iss" claim
	ClientID       string
}

func (c *OIDCCredential) Type() CredentialType {
	return CredentialTypeOIDC
}

// MTLSCredential represents client certificate authentication
type MTLSCredential struct {
	// TODO: use strongly typed fields that go gives us rather than raw bytes

	// Certificate is the client certificate (DER encoded)
	Certificate []byte

	// Chain is the certificate chain (DER encoded)
	Chain [][]byte

	// PeerCertificateHash for validation
	PeerCertificateHash string

	// IssuerIdentity identifies the CA/trust domain
	IssuerIdentity string
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
