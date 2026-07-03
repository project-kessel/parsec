package httpclient

import (
	"crypto/tls"
	"fmt"
)

// CertSource provides client certificates for mTLS.
// Implementations may read from files, Vault, K8s secrets, etc.
type CertSource interface {
	// Certificate returns the current client cert+key for TLS handshake.
	Certificate() (tls.Certificate, error)
}

// FileCertSource loads a client certificate and key from disk paths.
type FileCertSource struct {
	CertPath string
	KeyPath  string
}

// NewFileCertSource creates a [FileCertSource] that reads from the given paths.
func NewFileCertSource(certPath, keyPath string) *FileCertSource {
	return &FileCertSource{CertPath: certPath, KeyPath: keyPath}
}

// Certificate implements [CertSource].
func (s *FileCertSource) Certificate() (tls.Certificate, error) {
	cert, err := tls.LoadX509KeyPair(s.CertPath, s.KeyPath)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to load client certificate: %w", err)
	}
	return cert, nil
}
