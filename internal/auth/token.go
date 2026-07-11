package auth

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

// GenerateToken returns a new random API token (URL-safe hex) and its SHA-256
// hash. Only the hash is stored; the plaintext is shown to the user once.
func GenerateToken() (token, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generating token: %w", err)
	}
	token = "skry_" + hex.EncodeToString(buf)
	hash = HashToken(token)
	return token, hash, nil
}

// HashToken returns the SHA-256 hex hash of a token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}
