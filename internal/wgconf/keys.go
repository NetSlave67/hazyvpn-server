// Package wgconf generates WireGuard keys and renders/parses the textual
// .conf format for both server (tenant) interfaces and peer (road-warrior)
// configs.
package wgconf

import "golang.zx2c4.com/wireguard/wgctrl/wgtypes"

// Keypair is a WireGuard private/public key pair.
type Keypair struct {
	Private wgtypes.Key
	Public  wgtypes.Key
}

// GenerateKeypair creates a new Curve25519 keypair.
func GenerateKeypair() (Keypair, error) {
	priv, err := wgtypes.GeneratePrivateKey()
	if err != nil {
		return Keypair{}, err
	}
	return Keypair{Private: priv, Public: priv.PublicKey()}, nil
}

// GeneratePresharedKey creates a new preshared key for an extra layer of
// post-quantum-resistant symmetric encryption between a specific peer pair.
func GeneratePresharedKey() (wgtypes.Key, error) {
	return wgtypes.GenerateKey()
}

// ParseKey parses a base64-encoded WireGuard key string.
func ParseKey(s string) (wgtypes.Key, error) {
	return wgtypes.ParseKey(s)
}
