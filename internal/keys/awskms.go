package keys

import (
	"context"
	"crypto"
	"crypto/x509"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/kms"
	"github.com/aws/aws-sdk-go-v2/service/kms/types"
)

// AWSKMSKeyProvider is a KeyProvider backed by AWS KMS.
type AWSKMSKeyProvider struct {
	client      *kms.Client
	keyType     KeyType
	algorithm   string
	aliasPrefix string
	observer    AWSKMSProviderObserver
}

// AWSKMSConfig configures the AWS KMS key provider
type AWSKMSConfig struct {
	KeyType     KeyType
	Algorithm   string
	Region      string
	AliasPrefix string
	Client      *kms.Client
	Observer    AWSKMSProviderObserver
}

// NewAWSKMSKeyProvider creates a new AWS KMS key provider.
func NewAWSKMSKeyProvider(ctx context.Context, cfg AWSKMSConfig) (*AWSKMSKeyProvider, error) {
	if cfg.KeyType == "" {
		return nil, fmt.Errorf("key_type is required")
	}

	algorithm := cfg.Algorithm
	if algorithm == "" {
		// Determine default algorithm
		var err error
		algorithm, err = algorithmFromKeyType(cfg.KeyType)
		if err != nil {
			return nil, err
		}
	}

	var client *kms.Client

	if cfg.Client != nil {
		client = cfg.Client
	} else {
		// Load AWS config
		awsCfg, err := awsconfig.LoadDefaultConfig(ctx, awsconfig.WithRegion(cfg.Region))
		if err != nil {
			return nil, fmt.Errorf("failed to load AWS config: %w", err)
		}
		client = kms.NewFromConfig(awsCfg)
	}

	// Ensure alias prefix starts with "alias/"
	if cfg.AliasPrefix == "" {
		cfg.AliasPrefix = "alias/parsec/"
	}
	if len(cfg.AliasPrefix) < 6 || cfg.AliasPrefix[:6] != "alias/" {
		return nil, fmt.Errorf("alias prefix must start with 'alias/', got: %s", cfg.AliasPrefix)
	}

	obs := cfg.Observer
	if obs == nil {
		obs = NoOpAWSKMSProviderObserver{}
	}

	return &AWSKMSKeyProvider{
		client:      client,
		keyType:     cfg.KeyType,
		algorithm:   algorithm,
		aliasPrefix: cfg.AliasPrefix,
		observer:    obs,
	}, nil
}

func (m *AWSKMSKeyProvider) GetKeyHandle(ctx context.Context, trustDomain, namespace, keyName string) (KeyHandle, error) {
	return &awsKeyHandle{
		manager:     m,
		trustDomain: trustDomain,
		namespace:   namespace,
		keyName:     keyName,
	}, nil
}

func (m *AWSKMSKeyProvider) rotateKey(ctx context.Context, trustDomain, namespace, keyName string) error {
	aliasName := m.aliasName(trustDomain, namespace, keyName)
	ctx, p := m.observer.KMSRotateStarted(ctx, trustDomain, namespace, keyName)
	defer p.End()

	// 1. Create new KMS key (CMK) using configured keyType
	keySpec, err := keySpecFromKeyType(m.keyType)
	if err != nil {
		return err
	}

	createResp, err := m.client.CreateKey(ctx, &kms.CreateKeyInput{
		KeySpec:  keySpec,
		KeyUsage: types.KeyUsageTypeSignVerify,
	})
	if err != nil {
		p.CreateKeyFailed(err)
		return fmt.Errorf("failed to create KMS key: %w", err)
	}

	newKeyID := aws.ToString(createResp.KeyMetadata.KeyId)
	p.KeyCreated()

	// 2. Get current alias to find old key (if exists)
	oldKeyID, err := m.getKeyIDFromAlias(ctx, aliasName)
	if err != nil && oldKeyID == "" {
		// Alias doesn't exist yet
	} else if err != nil {
		p.AliasCheckFailed(err)
		return fmt.Errorf("failed to check existing alias: %w", err)
	}

	// 3. Create or update alias to point to new key
	if oldKeyID != "" {
		_, err = m.client.UpdateAlias(ctx, &kms.UpdateAliasInput{
			AliasName:   aws.String(aliasName),
			TargetKeyId: aws.String(newKeyID),
		})
		if err != nil {
			p.AliasUpdateFailed(err)
			return fmt.Errorf("failed to update alias: %w", err)
		}
		p.AliasChanged(false)
	} else {
		_, err = m.client.CreateAlias(ctx, &kms.CreateAliasInput{
			AliasName:   aws.String(aliasName),
			TargetKeyId: aws.String(newKeyID),
		})
		if err != nil {
			p.AliasUpdateFailed(err)
			return fmt.Errorf("failed to create alias: %w", err)
		}
		p.AliasChanged(true)
	}

	// 4. Schedule old key for deletion (7 days minimum)
	if oldKeyID != "" {
		_, err = m.client.ScheduleKeyDeletion(ctx, &kms.ScheduleKeyDeletionInput{
			KeyId:               aws.String(oldKeyID),
			PendingWindowInDays: aws.Int32(7),
		})
		if err != nil {
			p.OldKeyDeletionFailed(oldKeyID, err)
		} else {
			p.DeletionScheduled()
		}
	}

	return nil
}

func (m *AWSKMSKeyProvider) getKeyIDFromAlias(ctx context.Context, aliasName string) (string, error) {
	resp, err := m.client.DescribeKey(ctx, &kms.DescribeKeyInput{
		KeyId: aws.String(aliasName),
	})
	if err != nil {
		return "", err
	}
	// Use ARN, not KeyId. Despite the name, KeyMetadata.KeyId returns a UUID
	// while Sign's resp.KeyId returns a full ARN. We use ARN consistently
	// so the contextSigner mismatch check compares like with like.
	return aws.ToString(resp.KeyMetadata.Arn), nil
}

func (m *AWSKMSKeyProvider) aliasName(trustDomain, namespace, keyName string) string {
	// Build alias path with separate trust domain and namespace components
	var parts []string
	if trustDomain != "" {
		parts = append(parts, sanitizeAliasComponent(trustDomain))
	}
	if namespace != "" {
		parts = append(parts, sanitizeAliasComponent(namespace))
	}
	parts = append(parts, keyName)

	// Join all parts with "/" separator
	return fmt.Sprintf("%s%s", m.aliasPrefix, strings.Join(parts, "/"))
}

// awsKeyHandle implements KeyHandle
type awsKeyHandle struct {
	manager     *AWSKMSKeyProvider
	trustDomain string
	namespace   string
	keyName     string
}

func (h *awsKeyHandle) Sign(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, string, error) {
	aliasName := h.manager.aliasName(h.trustDomain, h.namespace, h.keyName)

	// Determine signing algorithm
	var signingAlg types.SigningAlgorithmSpec
	switch h.manager.algorithm {
	case "ES256":
		signingAlg = types.SigningAlgorithmSpecEcdsaSha256
	case "ES384":
		signingAlg = types.SigningAlgorithmSpecEcdsaSha384
	case "RS256":
		signingAlg = types.SigningAlgorithmSpecRsassaPkcs1V15Sha256
	default:
		return nil, "", fmt.Errorf("unsupported algorithm: %s", h.manager.algorithm)
	}

	// Call KMS Sign using ALIAS
	// KMS automatically resolves alias to current key ID
	resp, err := h.manager.client.Sign(ctx, &kms.SignInput{
		KeyId:            aws.String(aliasName),
		Message:          digest,
		MessageType:      types.MessageTypeDigest,
		SigningAlgorithm: signingAlg,
	})
	if err != nil {
		return nil, "", fmt.Errorf("KMS sign failed: %w", err)
	}

	// Return the DER-encoded signature as-is.
	// The JWX library handles DER-to-raw conversion for ECDSA internally
	// when using the crypto.Signer interface.
	return resp.Signature, aws.ToString(resp.KeyId), nil
}

func (h *awsKeyHandle) Metadata(ctx context.Context) (string, string, error) {
	aliasName := h.manager.aliasName(h.trustDomain, h.namespace, h.keyName)
	keyID, err := h.manager.getKeyIDFromAlias(ctx, aliasName)
	if err != nil {
		return "", "", err
	}
	if keyID == "" {
		return "", "", fmt.Errorf("alias not found: %s", aliasName)
	}
	return keyID, h.manager.algorithm, nil
}

func (h *awsKeyHandle) Public(ctx context.Context) (crypto.PublicKey, error) {
	aliasName := h.manager.aliasName(h.trustDomain, h.namespace, h.keyName)
	resp, err := h.manager.client.GetPublicKey(ctx, &kms.GetPublicKeyInput{
		KeyId: aws.String(aliasName),
	})
	if err != nil {
		return nil, err
	}

	pubKey, err := x509.ParsePKIXPublicKey(resp.PublicKey)
	if err != nil {
		return nil, err
	}
	return pubKey, nil
}

func (h *awsKeyHandle) Rotate(ctx context.Context) error {
	return h.manager.rotateKey(ctx, h.trustDomain, h.namespace, h.keyName)
}

// Helper functions
func keySpecFromKeyType(keyType KeyType) (types.KeySpec, error) {
	switch keyType {
	case KeyTypeECP256:
		return types.KeySpecEccNistP256, nil
	case KeyTypeECP384:
		return types.KeySpecEccNistP384, nil
	case KeyTypeRSA2048:
		return types.KeySpecRsa2048, nil
	case KeyTypeRSA4096:
		return types.KeySpecRsa4096, nil
	default:
		return "", fmt.Errorf("unsupported key type: %s", keyType)
	}
}

func algorithmFromKeyType(keyType KeyType) (string, error) {
	switch keyType {
	case KeyTypeECP256:
		return "ES256", nil
	case KeyTypeECP384:
		return "ES384", nil
	case KeyTypeRSA2048, KeyTypeRSA4096:
		return "RS256", nil
	default:
		return "", fmt.Errorf("unsupported key type: %s", keyType)
	}
}

// sanitizeAliasComponent replaces characters not allowed in KMS alias names.
// KMS aliases must match ^[a-zA-Z0-9:/_-]+$
func sanitizeAliasComponent(s string) string {
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return s
}
