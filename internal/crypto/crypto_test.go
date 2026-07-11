package crypto

import (
	"encoding/hex"
	"strings"
	"testing"
)

const testHexKey = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"

func TestRoundTrip(t *testing.T) {
	c, err := New(testHexKey)
	if err != nil {
		t.Fatal(err)
	}
	if !c.Enabled() {
		t.Fatal("expected cipher enabled")
	}
	msg := "shodan-api-key-secret"
	ct, err := c.EncryptString(msg)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(ct, msg) {
		t.Fatal("ciphertext leaks plaintext")
	}
	got, err := c.DecryptString(ct)
	if err != nil {
		t.Fatal(err)
	}
	if got != msg {
		t.Fatalf("round trip mismatch: %q != %q", got, msg)
	}
}

func TestUniqueNonces(t *testing.T) {
	c, _ := New(testHexKey)
	a, _ := c.EncryptString("same")
	b, _ := c.EncryptString("same")
	if a == b {
		t.Fatal("expected distinct ciphertexts for identical plaintext (random nonce)")
	}
}

func TestNoKey(t *testing.T) {
	c, err := New("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Enabled() {
		t.Fatal("expected disabled cipher for empty key")
	}
	if _, err := c.EncryptString("x"); err != ErrNoKey {
		t.Fatalf("expected ErrNoKey, got %v", err)
	}
	if c.Fingerprint() != "" {
		t.Fatal("expected empty fingerprint with no key")
	}
}

func TestTamperDetection(t *testing.T) {
	c, _ := New(testHexKey)
	ct, _ := c.EncryptString("secret")
	// Flip a byte in the decoded ciphertext by mangling the base64 tail.
	bad := ct[:len(ct)-2] + "AA"
	if _, err := c.DecryptString(bad); err == nil {
		t.Fatal("expected authentication failure on tampered ciphertext")
	}
}

func TestBase64Key(t *testing.T) {
	raw, _ := hex.DecodeString(testHexKey)
	// std base64 of the 32 raw bytes should also decode.
	c, err := New("AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=")
	if err != nil {
		t.Fatal(err)
	}
	fp := c.Fingerprint()
	c2, _ := New(testHexKey)
	if fp != c2.Fingerprint() {
		t.Fatalf("hex and base64 of same key should share fingerprint")
	}
	_ = raw
}

func TestFingerprintStable(t *testing.T) {
	c, _ := New(testHexKey)
	if len(c.Fingerprint()) != 16 {
		t.Fatalf("unexpected fingerprint length: %q", c.Fingerprint())
	}
}
