package netns

import (
	"fmt"
	"net"
	"strings"
)

// FirewallSpec describes the nftables ruleset to apply inside a single
// tenant's network namespace. Because each namespace has independent
// netfilter state, this ruleset can never affect, or be affected by,
// another tenant.
type FirewallSpec struct {
	WGSubnet     *net.IPNet // the tenant's WireGuard subnet, e.g. 10.8.0.0/24
	IsolatePeers bool       // drop peer-to-peer traffic within WGSubnet
	// Exceptions are destination addresses that stay reachable even when
	// IsolatePeers is set — e.g. a shared jump host or file server that
	// every road-warrior should still be able to reach in an otherwise
	// zero-trust (peer-isolated) tenant. Each must already be a specific
	// host or subnet the operator wants reachable; nil/empty means no
	// exceptions.
	Exceptions []*net.IPNet
}

// Ruleset renders the nftables ruleset text for spec, suitable for feeding
// to `nft -f -` inside the tenant's namespace. It always starts with
// `add table` + `flush table`: nft's declarative `table { chain { ... } }`
// syntax only ever *adds* the rules it lists — re-feeding the same table
// definition when it already exists does not replace its rules, it
// appends a second copy of them (rules are identified by an opaque handle,
// not content). Without the flush, every re-application of this ruleset
// (every tenant restart/reconcile) would leave the old rules in place and
// pile up duplicates forever. `add table` makes the first-ever call (where
// the table doesn't exist yet) safe too, since `flush` alone would fail on
// a table that was never created.
//
// Policy: default-drop forward, allow the tenant's WireGuard traffic out to
// the host link (and from there to the internet via NAT), allow established/
// related return traffic, and — when IsolatePeers is set — drop new
// connections between two addresses that are both inside the tenant's own
// WireGuard subnet, since WireGuard's AllowedIPs alone does not stop
// road-warriors from reaching each other through the server. Exceptions are
// placed *before* that drop rule — nftables evaluates rules in order within
// a chain, so a destination matched by an exception's accept rule never
// reaches the isolation drop rule at all, regardless of which peer it came
// from.
func Ruleset(spec FirewallSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet hazyvpn\n")
	fmt.Fprintf(&b, "flush table inet hazyvpn\n")
	fmt.Fprintf(&b, "table inet hazyvpn {\n")
	fmt.Fprintf(&b, "  chain forward {\n")
	fmt.Fprintf(&b, "    type filter hook forward priority 0; policy drop;\n")
	fmt.Fprintf(&b, "    ct state established,related accept\n")
	if spec.IsolatePeers {
		for _, exc := range spec.Exceptions {
			fmt.Fprintf(&b, "    ip daddr %s accept\n", exc)
		}
	}
	if spec.IsolatePeers && spec.WGSubnet != nil {
		fmt.Fprintf(&b, "    ip saddr %s ip daddr %s ct state new drop\n", spec.WGSubnet, spec.WGSubnet)
	}
	if spec.WGSubnet != nil {
		fmt.Fprintf(&b, "    ip saddr %s accept\n", spec.WGSubnet)
		fmt.Fprintf(&b, "    ip daddr %s accept\n", spec.WGSubnet)
	}
	fmt.Fprintf(&b, "  }\n")
	fmt.Fprintf(&b, "  chain postrouting {\n")
	fmt.Fprintf(&b, "    type nat hook postrouting priority 100; policy accept;\n")
	if spec.WGSubnet != nil {
		fmt.Fprintf(&b, "    ip saddr %s masquerade\n", spec.WGSubnet)
	}
	fmt.Fprintf(&b, "  }\n")
	fmt.Fprintf(&b, "}\n")
	return b.String()
}
