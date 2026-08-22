// Package authcrypto wraps the primitives auth needs: password hashing,
// one-time recovery codes, and random token generation. Kept separate from
// pkg/secret, which encrypts private keys for storage rather than verifying
// user-supplied secrets.
package authcrypto

import (
	"crypto/rand"
	"encoding/base32"
	"encoding/base64"
	"fmt"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

// HashPassword bcrypt-hashes a plaintext password for storage.
func HashPassword(plaintext string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(plaintext), bcrypt.DefaultCost)
	if err != nil {
		return "", fmt.Errorf("authcrypto: hash password: %w", err)
	}
	return string(hash), nil
}

// VerifyPassword reports whether plaintext matches a previously hashed
// password.
func VerifyPassword(hash, plaintext string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plaintext)) == nil
}

// RandomToken returns a URL-safe random token of n raw bytes, suitable for
// session cookies and CSRF tokens.
func RandomToken(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("authcrypto: random token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}

// recoveryAlphabet omits visually ambiguous characters (0/O, 1/I/L) so a
// human typing a recovery code from a printed sheet doesn't get tripped up.
const recoveryAlphabet = "23456789ABCDEFGHJKMNPQRSTUVWXYZ"

// GenerateRecoveryCodes returns n freshly generated one-time codes in
// XXXX-XXXX form, ready to display to the user exactly once.
func GenerateRecoveryCodes(n int) ([]string, error) {
	codes := make([]string, n)
	for i := range codes {
		code, err := recoveryCode()
		if err != nil {
			return nil, err
		}
		codes[i] = code
	}
	return codes, nil
}

func recoveryCode() (string, error) {
	raw := make([]byte, 8)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("authcrypto: generate recovery code: %w", err)
	}
	var b strings.Builder
	for i, x := range raw {
		if i == 4 {
			b.WriteByte('-')
		}
		b.WriteByte(recoveryAlphabet[int(x)%len(recoveryAlphabet)])
	}
	return b.String(), nil
}

// HashRecoveryCode normalises and hashes a recovery code the same way for
// generation and verification.
func HashRecoveryCode(code string) (string, error) {
	return HashPassword(NormalizeRecoveryCode(code))
}

// NormalizeRecoveryCode uppercases and strips whitespace so "ab12-cd34" and
// "AB12 CD34" both match what was generated.
func NormalizeRecoveryCode(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	return strings.Join(strings.Fields(code), "")
}

// base32Secret is exported for callers that need a TOTP-compatible secret
// without depending on this package's specific encoding choice elsewhere.
var base32Secret = base32.StdEncoding.WithPadding(base32.NoPadding)

// RandomBase32Secret returns a random base32 secret of n raw bytes, suitable
// for seeding a TOTP key by hand if ever needed outside the otp library's
// own generator.
func RandomBase32Secret(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("authcrypto: random secret: %w", err)
	}
	return base32Secret.EncodeToString(buf), nil
}
