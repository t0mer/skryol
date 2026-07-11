package auth

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// sessionTTL is how long a session cookie remains valid.
const sessionTTL = 12 * time.Hour

// sessionSigner mints and verifies stateless HMAC-signed session tokens.
type sessionSigner struct {
	secret []byte
}

func newSessionSigner(secret string) *sessionSigner {
	b := []byte(secret)
	if len(b) == 0 {
		// No configured secret: generate an ephemeral one (sessions reset on
		// restart, which is acceptable for a home-lab default).
		b = make([]byte, 32)
		_, _ = rand.Read(b)
	}
	return &sessionSigner{secret: b}
}

// mint returns a signed token "base64(user|exp).sig" for the given username.
func (s *sessionSigner) mint(username string) string {
	exp := time.Now().Add(sessionTTL).Unix()
	payload := base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf("%s|%d", username, exp)))
	return payload + "." + s.sign(payload)
}

// verify checks the token signature and expiry, returning the username.
func (s *sessionSigner) verify(token string) (string, bool) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", false
	}
	if subtle.ConstantTimeCompare([]byte(parts[1]), []byte(s.sign(parts[0]))) != 1 {
		return "", false
	}
	raw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	fields := strings.SplitN(string(raw), "|", 2)
	if len(fields) != 2 {
		return "", false
	}
	exp, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || time.Now().Unix() > exp {
		return "", false
	}
	return fields[0], true
}

func (s *sessionSigner) sign(payload string) string {
	mac := hmac.New(sha256.New, s.secret)
	mac.Write([]byte(payload))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}
