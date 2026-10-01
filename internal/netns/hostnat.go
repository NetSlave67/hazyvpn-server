package netns

import (
	"fmt"
	"strings"
)

// HostTenantPort is the information SyncHostPortForwarding needs for one
// tenant: which WireGuard listen port should be forwarded into that
// tenant's namespace.
type HostTenantPort struct {
	TenantID   int64
	ListenPort int
}

// HostRuleset renders the nftables table that forwards each tenant's UDP
// port to that tenant's namespace, and NATs their outbound internet traffic
// on the way back out. Because every tenant's wg0 interface lives inside
// its own namespace, it has no direct path to receive traffic from outside
// that namespace — the DNAT rules bridge the inbound direction.
//
// The outbound direction needs its own fix too, found live: a tenant
// namespace's own postrouting chain (see Ruleset) already MASQUERADEs its
// WireGuard subnet to a link-local address in LinkRangeCIDR before routing
// out to the container's namespace — but that link-local address isn't
// globally routable, and Docker's own NAT only covers traffic sourced from
// its own bridge subnet, not this one. Without a second MASQUERADE here,
// a client's internet-bound traffic reaches exactly as far as that
// link-local hop and no further (confirmed live: it was the last hop a
// traceroute could reach), even though the client could still reach the
// tenant's own gateway address just fine.
//
// Despite the name, this table runs inside the hazyvpn-server *container's*
// own top-level network namespace, not the true Docker host's root
// namespace — a process inside a container has no way to reach the real
// host's namespace directly (that would need --net=host or an nsenter into
// the host's PID 1, neither of which this design uses). That's fine for the
// deployment this project targets: docker-compose publishes each tenant's
// port via Docker's own port-publishing DNAT, which already does the real
// host → container hop; this table only needs to pick up from there and
// route into the nested tenant namespace, confirmed to work end-to-end
// against a live container (see git history around the bug it replaced).
//
// This table only adds DNAT/accept rules; it never sets a restrictive
// default policy, so it can't interfere with Docker's own iptables/nftables
// management of the container's namespace.
//
// Like Ruleset, this always starts with `add table` + `flush table` so
// re-applying it (every tenant create/delete) replaces the rules instead
// of appending a second copy of them on top — found live in production: a
// tenant restored from backup under a new name reused the original
// tenant's listen port, and without the flush both tenants' DNAT rules
// coexisted in the same chain, leaving it up to nft's within-chain
// evaluation order which tenant's traffic actually got there.
func HostRuleset(tenants []HostTenantPort) (string, error) {
	var b strings.Builder
	b.WriteString("add table ip hazyvpn_host\n")
	b.WriteString("flush table ip hazyvpn_host\n")
	b.WriteString("table ip hazyvpn_host {\n")
	b.WriteString("  chain prerouting {\n")
	b.WriteString("    type nat hook prerouting priority -100; policy accept;\n")
	for _, t := range tenants {
		_, nsLink, _, err := LinkAddresses(t.TenantID)
		if err != nil {
			return "", fmt.Errorf("netns: computing link address for tenant %d: %w", t.TenantID, err)
		}
		fmt.Fprintf(&b, "    udp dport %d dnat to %s:%d\n", t.ListenPort, nsLink, t.ListenPort)
	}
	b.WriteString("  }\n")
	b.WriteString("  chain forward {\n")
	b.WriteString("    type filter hook forward priority 0; policy accept;\n")
	for _, t := range tenants {
		_, nsLink, _, err := LinkAddresses(t.TenantID)
		if err != nil {
			return "", fmt.Errorf("netns: computing link address for tenant %d: %w", t.TenantID, err)
		}
		fmt.Fprintf(&b, "    ip daddr %s udp dport %d accept\n", nsLink, t.ListenPort)
	}
	b.WriteString("  }\n")
	b.WriteString("  chain postrouting {\n")
	b.WriteString("    type nat hook postrouting priority 100; policy accept;\n")
	fmt.Fprintf(&b, "    ip saddr %s masquerade\n", LinkRangeCIDR)
	b.WriteString("  }\n")
	b.WriteString("}\n")
	return b.String(), nil
}

// SyncHostPortForwarding replaces the hazyvpn_host nftables table (see
// HostRuleset for exactly which namespace this runs in) with the forwarding
// rules for exactly the given tenants. Callers
// regenerate this from the full current tenant list every time a tenant is
// created or destroyed — at self-hosted scale a full replace is simpler and
// just as fast as tracking individual rule handles.
func (m *Manager) SyncHostPortForwarding(tenants []HostTenantPort) error {
	ruleset, err := HostRuleset(tenants)
	if err != nil {
		return err
	}
	if _, err := m.run.RunStdin("nft", ruleset, "-f", "-"); err != nil {
		return fmt.Errorf("netns: applying host port-forwarding rules: %w", err)
	}
	return nil
}
