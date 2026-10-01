package cryptutil

import (
	"path/filepath"
	"testing"
)

func TestSealOpenRoundTrip(t *testing.T) {
	var key [KeySize]byte
	for i := range key {
		key[i] = byte(i)
	}
	s := NewSealer(key)

	sealed, err := s.SealString("super-secret-private-key")
	if err != nil {
		t.Fatalf("SealString: %v", err)
	}
	opened, err := s.OpenString(sealed)
	if err != nil {
		t.Fatalf("OpenString: %v", err)
	}
	if opened != "super-secret-private-key" {
		t.Fatalf("round trip mismatch: got %q", opened)
	}
}

func TestSealProducesDistinctCiphertextsForSameInput(t *testing.T) {
	var key [KeySize]byte
	s := NewSealer(key)
	a, _ := s.SealString("same-input")
	b, _ := s.SealString("same-input")
	if string(a) == string(b) {
		t.Fatal("expected distinct ciphertexts due to random nonce")
	}
}

func TestLoadOrCreateMasterKeyPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "nested", "server.key")

	k1, err := LoadOrCreateMasterKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateMasterKey (create): %v", err)
	}
	k2, err := LoadOrCreateMasterKey(path)
	if err != nil {
		t.Fatalf("LoadOrCreateMasterKey (reload): %v", err)
	}
	if k1 != k2 {
		t.Fatal("master key changed across reload")
	}
}
