// Package crypto provides AES-256-GCM encryption for secrets at rest.
//
// The 32-byte key is operator-owned infrastructure, provisioned via
// SKRYOL_CRYPTO_ENCRYPTION_KEY. It may be supplied as a 64-character hex string
// or standard/base64 (with or without padding). Ciphertext is stored as base64
// of nonce||ciphertext||tag.
package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ErrNoKey indicates no encryption key was configured but a secret operation
// was attempted.
var ErrNoKey = errors.New("crypto: encryption key not configured (set SKRYOL_CRYPTO_ENCRYPTION_KEY)")

// Cipher performs authenticated encryption with a fixed 256-bit key.
type Cipher struct {
	aead cipher.AEAD
	key  []byte
}

// New builds a Cipher from the configured key material. An empty rawKey yields a
// Cipher whose operations return ErrNoKey, so callers can construct it
// unconditionally and fail only when a secret is actually used.
func New(rawKey string) (*Cipher, error) {
	rawKey = strings.TrimSpace(rawKey)
	if rawKey == "" {
		return &Cipher{}, nil
	}
	key, err := decodeKey(rawKey)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: building cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: building GCM: %w", err)
	}
	return &Cipher{aead: aead, key: key}, nil
}

// NewFromRawKey builds a Cipher from exactly 32 raw key bytes (e.g. a
// passphrase-derived key). Used by export/import for portable re-encryption.
func NewFromRawKey(key []byte) (*Cipher, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("crypto: raw key must be 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("crypto: building cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: building GCM: %w", err)
	}
	dup := make([]byte, len(key))
	copy(dup, key)
	return &Cipher{aead: aead, key: dup}, nil
}

// decodeKey parses a 32-byte key from hex or base64.
func decodeKey(s string) ([]byte, error) {
	if len(s) == 64 {
		if b, err := hex.DecodeString(s); err == nil {
			return b, nil
		}
	}
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.RawStdEncoding,
		base64.URLEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(s); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	// Fall back to using the raw bytes if exactly 32 bytes.
	if len(s) == 32 {
		return []byte(s), nil
	}
	return nil, fmt.Errorf("crypto: encryption key must be 32 bytes (hex or base64), got %d chars", len(s))
}

// Enabled reports whether a usable key is configured.
func (c *Cipher) Enabled() bool { return c.aead != nil }

// Encrypt seals plaintext and returns base64(nonce||ciphertext).
func (c *Cipher) Encrypt(plaintext []byte) (string, error) {
	if c.aead == nil {
		return "", ErrNoKey
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("crypto: generating nonce: %w", err)
	}
	sealed := c.aead.Seal(nonce, nonce, plaintext, nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// EncryptString is a convenience wrapper over Encrypt.
func (c *Cipher) EncryptString(s string) (string, error) { return c.Encrypt([]byte(s)) }

// Decrypt opens a base64(nonce||ciphertext) value produced by Encrypt.
func (c *Cipher) Decrypt(encoded string) ([]byte, error) {
	if c.aead == nil {
		return nil, ErrNoKey
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("crypto: decoding ciphertext: %w", err)
	}
	ns := c.aead.NonceSize()
	if len(data) < ns {
		return nil, errors.New("crypto: ciphertext too short")
	}
	nonce, ct := data[:ns], data[ns:]
	plain, err := c.aead.Open(nil, nonce, ct, nil)
	if err != nil {
		return nil, fmt.Errorf("crypto: authentication failed: %w", err)
	}
	return plain, nil
}

// DecryptString opens a ciphertext into a string.
func (c *Cipher) DecryptString(encoded string) (string, error) {
	b, err := c.Decrypt(encoded)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// Fingerprint returns a non-reversible identifier for the configured key,
// suitable for verifying two instances share the same key without exposing it.
// Returns "" when no key is configured.
func (c *Cipher) Fingerprint() string {
	if len(c.key) == 0 {
		return ""
	}
	// Domain-separated hash so the fingerprint can't be used as an oracle.
	sum := sha256.Sum256(append([]byte("skryol-key-fingerprint\x00"), c.key...))
	return hex.EncodeToString(sum[:8])
}
