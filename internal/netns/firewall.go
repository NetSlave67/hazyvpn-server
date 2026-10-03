package netns

import (
	"fmt"
	"net"
	"strings"
)

// FirewallRule is one ordered entry in a tenant's custom firewall — see
// store.FirewallRule for the full rationale (it mirrors this type). Action
// is "allow" or "block"; Address empty means any address; Port 0 means any
// port; Protocol empty (with Port set) means both tcp and udp.
type FirewallRule struct {
	Action   string
	Address  string
	Port     int
	Protocol string
}

// FirewallSpec describes the nftables ruleset to apply inside a single
// tenant's network namespace. Because each namespace has independent
// netfilter state, this ruleset can never affect, or be affected by,
// another tenant.
type FirewallSpec struct {
	WGSubnet     *net.IPNet // the tenant's WireGuard subnet, e.g. 10.8.0.0/24
	IsolatePeers bool       // drop peer-to-peer traffic within WGSubnet
	// Rules are the operator's custom allow/block entries, in evaluation
	// order (first match wins) — always applied, regardless of
	// IsolatePeers, since a block rule should hold whether or not peer
	// isolation happens to be on.
	Rules []FirewallRule
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
// related return traffic, then the operator's Rules in order, then — when
// IsolatePeers is set — drop new connections between two addresses that are
// both inside the tenant's own WireGuard subnet, since WireGuard's
// AllowedIPs alone does not stop road-warriors from reaching each other
// through the server. Rules are placed *before* that drop (and before the
// default subnet-accept below it) — nftables evaluates a chain's rules in
// order and the first match wins, so an explicit allow can override the
// isolation drop, and an explicit block can override the default "allow
// everything else" behavior, exactly like a real firewall's rule list.
func Ruleset(spec FirewallSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "add table inet hazyvpn\n")
	fmt.Fprintf(&b, "flush table inet hazyvpn\n")
	fmt.Fprintf(&b, "table inet hazyvpn {\n")
	fmt.Fprintf(&b, "  chain forward {\n")
	fmt.Fprintf(&b, "    type filter hook forward priority 0; policy drop;\n")
	fmt.Fprintf(&b, "    ct state established,related accept\n")
	for _, r := range spec.Rules {
		fmt.Fprintf(&b, "    %s %s\n", ruleMatch(r), ruleVerdict(r))
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

// ruleMatch renders the match expression for a rule — everything except
// the final accept/drop verdict.
func ruleMatch(r FirewallRule) string {
	var parts []string
	if r.Address != "" {
		parts = append(parts, fmt.Sprintf("ip daddr %s", r.Address))
	}
	if r.Port != 0 {
		switch r.Protocol {
		case "tcp", "udp":
			parts = append(parts, fmt.Sprintf("%s dport %d", r.Protocol, r.Port))
		default:
			// No protocol specified: match the port under both tcp and
			// udp. `th dport` reads the transport header's destination
			// port field, which exists at the same offset for both.
			parts = append(parts, fmt.Sprintf("meta l4proto { tcp, udp } th dport %d", r.Port))
		}
	}
	return strings.Join(parts, " ")
}

func ruleVerdict(r FirewallRule) string {
	if r.Action == "block" {
		return "drop"
	}
	return "accept"
}
