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
// port to that tenant's namespace. Because every tenant's wg0 interface
// lives inside its own namespace, it has no direct path to receive traffic
// from outside that namespace — this DNAT rule is what bridges the two.
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
func HostRuleset(tenants []HostTenantPort) (string, error) {
	var b strings.Builder
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
