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
}

// Ruleset renders the nftables ruleset text for spec, suitable for feeding
// to `nft -f -` inside the tenant's namespace.
//
// Policy: default-drop forward, allow the tenant's WireGuard traffic out to
// the host link (and from there to the internet via NAT), allow established/
// related return traffic, and — when IsolatePeers is set — drop new
// connections between two addresses that are both inside the tenant's own
// WireGuard subnet, since WireGuard's AllowedIPs alone does not stop
// road-warriors from reaching each other through the server.
func Ruleset(spec FirewallSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "table inet hazyvpn {\n")
	fmt.Fprintf(&b, "  chain forward {\n")
	fmt.Fprintf(&b, "    type filter hook forward priority 0; policy drop;\n")
	fmt.Fprintf(&b, "    ct state established,related accept\n")
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
