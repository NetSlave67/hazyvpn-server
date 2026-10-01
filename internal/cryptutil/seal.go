// Package cryptutil encrypts WireGuard private/preshared keys at rest using
// a server-local master key, so the SQLite database alone is never enough to
// reconstruct a peer's tunnel.
package cryptutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// KeySize is the AES-256 master key size in bytes.
const KeySize = 32

// Sealer encrypts and decrypts small secrets (WireGuard keys) with a fixed
// AES-256-GCM master key.
type Sealer struct {
	key [KeySize]byte
}

// NewSealer builds a Sealer from an existing 32-byte master key.
func NewSealer(key [KeySize]byte) *Sealer {
	return &Sealer{key: key}
}

// LoadOrCreateMasterKey reads a 32-byte master key from path, generating and
// persisting a new random one (mode 0600) if the file doesn't exist yet.
func LoadOrCreateMasterKey(path string) ([KeySize]byte, error) {
	var key [KeySize]byte

	data, err := os.ReadFile(path)
	if err == nil {
		if len(data) != KeySize {
			return key, fmt.Errorf("cryptutil: master key at %s is %d bytes, want %d", path, len(data), KeySize)
		}
		copy(key[:], data)
		return key, nil
	}
	if !os.IsNotExist(err) {
		return key, fmt.Errorf("cryptutil: reading master key: %w", err)
	}

	if _, err := io.ReadFull(rand.Reader, key[:]); err != nil {
		return key, fmt.Errorf("cryptutil: generating master key: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return key, fmt.Errorf("cryptutil: creating key directory: %w", err)
	}
	if err := os.WriteFile(path, key[:], 0o600); err != nil {
		return key, fmt.Errorf("cryptutil: writing master key: %w", err)
	}
	return key, nil
}

// Seal encrypts plaintext, returning nonce||ciphertext.
func (s *Sealer) Seal(plaintext []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

// Open decrypts a value produced by Seal.
func (s *Sealer) Open(sealed []byte) ([]byte, error) {
	block, err := aes.NewCipher(s.key[:])
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(sealed) < gcm.NonceSize() {
		return nil, fmt.Errorf("cryptutil: sealed value too short")
	}
	nonce, ciphertext := sealed[:gcm.NonceSize()], sealed[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}

// SealString is a convenience wrapper for Seal on string secrets (keys are
// always printable base64 in WireGuard).
func (s *Sealer) SealString(plaintext string) ([]byte, error) {
	if plaintext == "" {
		return nil, nil
	}
	return s.Seal([]byte(plaintext))
}

// OpenString is a convenience wrapper for Open returning a string.
func (s *Sealer) OpenString(sealed []byte) (string, error) {
	if len(sealed) == 0 {
		return "", nil
	}
	out, err := s.Open(sealed)
	if err != nil {
		return "", err
	}
	return string(out), nil
}
