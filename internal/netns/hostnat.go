package netns

import (
	"fmt"
	"strings"
)

// HostTenantPort is the information SyncHostPortForwarding needs for one
// tenant: which WireGuard listen port on the host's public IP should be
// forwarded into that tenant's namespace.
type HostTenantPort struct {
	TenantID   int64
	ListenPort int
}

// HostRuleset renders the single, host-level (not namespaced) nftables
// table that forwards each tenant's public UDP port to that tenant's
// namespace. Because every tenant's wg0 interface lives inside its own
// namespace, it has no direct path to the host's public interface — this
// DNAT rule is what makes the tenant reachable from outside at all.
//
// This table only adds DNAT/accept rules; it never sets a restrictive
// default policy, so it can't interfere with Docker's own iptables/nftables
// management of the host.
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

// SyncHostPortForwarding replaces the host's hazyvpn_host nftables table
// with the forwarding rules for exactly the given tenants. Callers
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
