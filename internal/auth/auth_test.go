package auth

import "testing"

func TestPasswordHashVerify(t *testing.T) {
	hash, err := HashPassword("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !VerifyPassword("correct horse battery staple", hash) {
		t.Fatal("expected correct password to verify")
	}
	if VerifyPassword("wrong", hash) {
		t.Fatal("expected wrong password to fail")
	}
	if VerifyPassword("x", "not-a-phc-string") {
		t.Fatal("malformed hash should not verify")
	}
}

func TestPasswordUniqueSalts(t *testing.T) {
	a, _ := HashPassword("same")
	b, _ := HashPassword("same")
	if a == b {
		t.Fatal("expected distinct hashes due to random salt")
	}
}

func TestTokenHashDeterministic(t *testing.T) {
	tok, hash, err := GenerateToken()
	if err != nil {
		t.Fatal(err)
	}
	if HashToken(tok) != hash {
		t.Fatal("HashToken must match GenerateToken's hash")
	}
	if len(tok) < 20 {
		t.Fatalf("token too short: %q", tok)
	}
}

func TestSessionSignVerify(t *testing.T) {
	s := newSessionSigner("test-secret")
	token := s.mint("admin")
	user, ok := s.verify(token)
	if !ok || user != "admin" {
		t.Fatalf("expected valid session for admin, got %q ok=%v", user, ok)
	}
	if _, ok := s.verify(token + "tamper"); ok {
		t.Fatal("tampered session must not verify")
	}
	other := newSessionSigner("different-secret")
	if _, ok := other.verify(token); ok {
		t.Fatal("session signed with a different secret must not verify")
	}
}
