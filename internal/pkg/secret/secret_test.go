package secret

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func newKey(t *testing.T) string {
	t.Helper()
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("rand: %v", err)
	}
	return base64.StdEncoding.EncodeToString(raw)
}

func TestSealRoundTrip(t *testing.T) {
	s, err := NewSealer(newKey(t))
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if !s.Enabled() {
		t.Fatal("sealer should be enabled")
	}

	plaintext := "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"
	sealed, err := s.Seal(plaintext)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}
	if sealed == plaintext {
		t.Fatal("Seal returned the plaintext")
	}
	opened, err := s.Open(sealed, true)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	if opened != plaintext {
		t.Errorf("round trip = %q", opened)
	}
}

func TestSealIsNonDeterministic(t *testing.T) {
	s, _ := NewSealer(newKey(t))
	a, _ := s.Seal("same input")
	b, _ := s.Seal("same input")
	if a == b {
		t.Error("two seals of the same plaintext produced identical ciphertext")
	}
}

func TestOpenWithWrongKeyFails(t *testing.T) {
	a, _ := NewSealer(newKey(t))
	b, _ := NewSealer(newKey(t))
	sealed, _ := a.Seal("secret")
	if _, err := b.Open(sealed, false); err != nil {
		t.Error("an unencrypted value should pass through untouched")
	}
	if _, err := b.Open(sealed, true); err == nil {
		t.Error("expected authentication to fail with the wrong key")
	}
}

func TestDisabledSealerPassesThrough(t *testing.T) {
	s, err := NewSealer("")
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	if s.Enabled() {
		t.Fatal("empty key must not enable encryption")
	}
	out, err := s.Seal("plain")
	if err != nil || out != "plain" {
		t.Errorf("Seal = %q, %v", out, err)
	}
	if _, err := s.Open("anything", true); err != ErrNoKey {
		t.Errorf("Open with no key = %v, want ErrNoKey", err)
	}
}

func TestShortKeyRejected(t *testing.T) {
	if _, err := NewSealer(base64.StdEncoding.EncodeToString([]byte("too short"))); err == nil {
		t.Fatal("expected an error for a key that is not 32 bytes")
	}
	if _, err := NewSealer("not base64 !!!"); err == nil {
		t.Fatal("expected an error for a non-base64 key")
	}
}
