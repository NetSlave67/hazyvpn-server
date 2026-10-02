package netns

import (
	"fmt"
	"strings"
)

// SyncRoutedPrefixes replaces a tenant namespace's extra kernel routes
// (beyond its own connected WireGuard subnet) with exactly the given
// prefixes, each pointed at wg0.
//
// This exists because of something easy to miss: WireGuard's own AllowedIPs
// only controls its *internal* crypto-routing — which peer a packet gets
// encrypted for, once the kernel has already decided to send it out via
// wg0. It never adds anything to the kernel's actual routing table; that's
// normally wg-quick's job (it calls `ip route add` for every AllowedIPs
// entry), but this server talks to `wg` directly via SyncWireGuard's
// `wg syncconf`, never wg-quick. So a peer's RoutedPrefixes showing up
// correctly in `wg show` does not mean the kernel will ever consider
// sending matching traffic out wg0 at all — confirmed live: `ip route`
// inside the namespace showed nothing for a routed prefix `wg show`
// already listed correctly. A peer's own address needs no such route
// because the subnet-wide address assigned to wg0 itself already creates
// a connected route covering the whole subnet; RoutedPrefixes, by
// definition, lie outside that subnet.
//
// subnet is the tenant's own connected subnet (as `ip route show` reports
// it) — never touched, regardless of what's in prefixes. Idempotent: diffs
// against whatever's currently on wg0 rather than blindly re-adding, since
// `ip route add` errors on a route that already exists.
func (m *Manager) SyncRoutedPrefixes(tenantID int64, subnet string, prefixes []string) error {
	ns := Namespace(tenantID)

	for _, family := range []string{"-4", "-6"} {
		desired := map[string]bool{}
		for _, p := range prefixes {
			if isIPv6CIDR(p) == (family == "-6") {
				desired[p] = true
			}
		}

		current, err := m.currentExtraRoutes(ns, family, subnet)
		if err != nil {
			return err
		}

		for dest := range current {
			if desired[dest] {
				continue
			}
			if _, err := m.run.Run("ip", "netns", "exec", ns, "ip", family, "route", "del", dest, "dev", WGInterface); err != nil {
				return fmt.Errorf("netns: removing stale route %s: %w", dest, err)
			}
		}
		for dest := range desired {
			if current[dest] {
				continue
			}
			if _, err := m.run.Run("ip", "netns", "exec", ns, "ip", family, "route", "add", dest, "dev", WGInterface); err != nil {
				return fmt.Errorf("netns: adding route %s: %w", dest, err)
			}
		}
	}
	return nil
}

// currentExtraRoutes lists the routes currently on wg0 for one address
// family, excluding the tenant's own connected subnet route.
func (m *Manager) currentExtraRoutes(ns, family, subnet string) (map[string]bool, error) {
	out, err := m.run.Run("ip", "netns", "exec", ns, "ip", family, "route", "show", "dev", WGInterface)
	if err != nil {
		return nil, fmt.Errorf("netns: listing routes: %w", err)
	}
	routes := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		dest := strings.Fields(line)[0]
		if dest == subnet {
			continue // the interface's own connected subnet — never managed here
		}
		routes[dest] = true
	}
	return routes, nil
}

// isIPv6CIDR reports whether a CIDR/IP string is IPv6, by the presence of
// a colon — good enough to route "-4" vs "-6" to the right `ip` invocation
// without pulling in full address parsing for what's already been
// validated as a syntactically correct CIDR by the app layer.
func isIPv6CIDR(s string) bool {
	return strings.Contains(s, ":")
}
