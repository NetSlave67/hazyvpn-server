package wgconf

import (
	"fmt"
	"strings"
)

// PeerConfig holds everything needed to render a road-warrior's client-side
// .conf file. Fields map 1:1 onto tenant defaults, each overridable per peer.
type PeerConfig struct {
	Name                string // comment only, not written to [Interface]/[Peer] keys
	PrivateKey          string
	Address             string // e.g. "10.8.0.2/24"
	DNS                 string // e.g. "1.1.1.1, 1.0.0.1" — empty to omit
	ServerPublicKey     string
	PresharedKey        string // empty to omit
	Endpoint            string // "host:port"
	AllowedIPs          string // e.g. "0.0.0.0/0, ::/0"
	PersistentKeepalive int    // 0 to omit
}

// RenderPeerConfig renders the client-side WireGuard config for a single
// road-warrior peer.
func RenderPeerConfig(c PeerConfig) string {
	var b strings.Builder
	if c.Name != "" {
		fmt.Fprintf(&b, "# %s\n", c.Name)
	}
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.PrivateKey)
	fmt.Fprintf(&b, "Address = %s\n", c.Address)
	if c.DNS != "" {
		fmt.Fprintf(&b, "DNS = %s\n", c.DNS)
	}
	b.WriteString("\n[Peer]\n")
	fmt.Fprintf(&b, "PublicKey = %s\n", c.ServerPublicKey)
	if c.PresharedKey != "" {
		fmt.Fprintf(&b, "PresharedKey = %s\n", c.PresharedKey)
	}
	fmt.Fprintf(&b, "Endpoint = %s\n", c.Endpoint)
	fmt.Fprintf(&b, "AllowedIPs = %s\n", c.AllowedIPs)
	if c.PersistentKeepalive > 0 {
		fmt.Fprintf(&b, "PersistentKeepalive = %d\n", c.PersistentKeepalive)
	}
	return b.String()
}

// ServerPeerSection is one [Peer] block within a tenant's server-side
// interface config — i.e. one road-warrior as seen from the server.
type ServerPeerSection struct {
	Name         string // comment only
	PublicKey    string
	PresharedKey string // empty to omit
	AllowedIPs   string // typically the peer's single /32 (or /128) address
}

// ServerInterfaceConfig holds everything needed to render a tenant's
// server-side WireGuard interface config. This is fed directly to
// `wg syncconf` (see netns.Manager.SyncWireGuard), not `wg-quick` — unlike
// PeerConfig, it must stick to the handful of directives the plain wg(8)
// config parser understands (PrivateKey/ListenPort/FwMark and, per peer,
// PublicKey/PresharedKey/AllowedIPs/Endpoint/PersistentKeepalive) — the
// same strict set for `syncconf` as for `setconf`, since both share that
// parser. Address is deliberately not a field here: it gets rejected
// outright ("Line unrecognized"), and the tenant's own address is assigned
// separately via `ip addr add` when its namespace is created (see
// netns.Manager.Create).
type ServerInterfaceConfig struct {
	PrivateKey string
	ListenPort int
	Peers      []ServerPeerSection
}

// RenderServerConfig renders a tenant's server-side interface config,
// including all of its peers.
func RenderServerConfig(c ServerInterfaceConfig) string {
	var b strings.Builder
	b.WriteString("[Interface]\n")
	fmt.Fprintf(&b, "PrivateKey = %s\n", c.PrivateKey)
	fmt.Fprintf(&b, "ListenPort = %d\n", c.ListenPort)

	for _, p := range c.Peers {
		b.WriteString("\n[Peer]\n")
		if p.Name != "" {
			fmt.Fprintf(&b, "# %s\n", p.Name)
		}
		fmt.Fprintf(&b, "PublicKey = %s\n", p.PublicKey)
		if p.PresharedKey != "" {
			fmt.Fprintf(&b, "PresharedKey = %s\n", p.PresharedKey)
		}
		fmt.Fprintf(&b, "AllowedIPs = %s\n", p.AllowedIPs)
	}
	return b.String()
}
