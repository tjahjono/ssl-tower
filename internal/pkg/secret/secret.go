// Package secret provides envelope encryption for private key material at rest.
//
// When APP_ENCRYPTION_KEY is configured the private key PEM stored in Postgres is
// AES-256-GCM ciphertext; when it is empty the PEM is stored verbatim and the row
// is flagged so the UI can warn about it.
package secret

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
)

// ErrNoKey is returned when decryption is attempted without a configured key.
var ErrNoKey = errors.New("secret: no encryption key configured")

// Sealer encrypts and decrypts small blobs. A zero Sealer is a valid no-op sealer.
type Sealer struct {
	aead cipher.AEAD
}

// NewSealer builds a Sealer from a base64 (std or raw) encoded 32-byte key.
// An empty key yields a no-op Sealer whose Enabled method reports false.
func NewSealer(base64Key string) (*Sealer, error) {
	if base64Key == "" {
		return &Sealer{}, nil
	}
	key, err := decodeKey(base64Key)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("secret: encryption key must decode to 32 bytes, got %d", len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secret: new cipher: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("secret: new gcm: %w", err)
	}
	return &Sealer{aead: aead}, nil
}

// Enabled reports whether encryption is active.
func (s *Sealer) Enabled() bool { return s != nil && s.aead != nil }

// Seal encrypts plaintext and returns base64(nonce||ciphertext).
// With no key configured it returns the plaintext unchanged.
func (s *Sealer) Seal(plaintext string) (string, error) {
	if !s.Enabled() {
		return plaintext, nil
	}
	nonce := make([]byte, s.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", fmt.Errorf("secret: nonce: %w", err)
	}
	sealed := s.aead.Seal(nonce, nonce, []byte(plaintext), nil)
	return base64.StdEncoding.EncodeToString(sealed), nil
}

// Open reverses Seal. encrypted reports how the value was stored, which lets a
// database that predates the encryption key still be read.
func (s *Sealer) Open(stored string, encrypted bool) (string, error) {
	if !encrypted {
		return stored, nil
	}
	if !s.Enabled() {
		return "", ErrNoKey
	}
	raw, err := base64.StdEncoding.DecodeString(stored)
	if err != nil {
		return "", fmt.Errorf("secret: decode: %w", err)
	}
	if len(raw) < s.aead.NonceSize() {
		return "", errors.New("secret: ciphertext too short")
	}
	nonce, body := raw[:s.aead.NonceSize()], raw[s.aead.NonceSize():]
	out, err := s.aead.Open(nil, nonce, body, nil)
	if err != nil {
		return "", fmt.Errorf("secret: open: %w", err)
	}
	return string(out), nil
}

func decodeKey(s string) ([]byte, error) {
	if k, err := base64.StdEncoding.DecodeString(s); err == nil {
		return k, nil
	}
	k, err := base64.RawStdEncoding.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("secret: encryption key must be base64: %w", err)
	}
	return k, nil
}
