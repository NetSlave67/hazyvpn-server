package netns

import (
	"net"
	"strings"
	"testing"
)

func TestRulesetDefaultDropsForward(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.8.0.0/24")
	out := Ruleset(FirewallSpec{WGSubnet: subnet, IsolatePeers: true})
	if !strings.Contains(out, "policy drop") {
		t.Fatal("expected default-drop forward policy")
	}
	if !strings.Contains(out, "masquerade") {
		t.Fatal("expected NAT masquerade rule for the tenant subnet")
	}
}

func TestRulesetIsolatePeersAddsDropRule(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.8.0.0/24")
	isolated := Ruleset(FirewallSpec{WGSubnet: subnet, IsolatePeers: true})
	open := Ruleset(FirewallSpec{WGSubnet: subnet, IsolatePeers: false})

	if !strings.Contains(isolated, "ct state new drop") {
		t.Fatal("expected a peer-isolation drop rule when IsolatePeers is true")
	}
	if strings.Contains(open, "ct state new drop") {
		t.Fatal("did not expect a peer-isolation drop rule when IsolatePeers is false")
	}
}

func TestRulesetAllowRuleAcceptsBeforeIsolationDrop(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.8.0.0/24")
	out := Ruleset(FirewallSpec{
		WGSubnet: subnet, IsolatePeers: true,
		Rules: []FirewallRule{{Action: "allow", Address: "10.8.0.5"}},
	})

	acceptIdx := strings.Index(out, "ip daddr 10.8.0.5 accept")
	dropIdx := strings.Index(out, "ct state new drop")
	if acceptIdx < 0 {
		t.Fatalf("expected an accept rule for the allowed address, got:\n%s", out)
	}
	if dropIdx < 0 {
		t.Fatalf("expected the isolation drop rule to still be present, got:\n%s", out)
	}
	if acceptIdx > dropIdx {
		t.Fatalf("an allow rule must come before the isolation drop rule (nft evaluates in order), got:\n%s", out)
	}
}

// TestRulesetBlockRuleAppliesRegardlessOfIsolatePeers is the key behavioral
// difference from the old "isolation exceptions" field: a custom rule is a
// general firewall control, not something scoped to peer isolation — a
// block for a specific address/port must take effect whether or not
// IsolatePeers happens to be on.
func TestRulesetBlockRuleAppliesRegardlessOfIsolatePeers(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.8.0.0/24")
	out := Ruleset(FirewallSpec{
		WGSubnet: subnet, IsolatePeers: false,
		Rules: []FirewallRule{{Action: "block", Address: "198.51.100.9"}},
	})
	if !strings.Contains(out, "ip daddr 198.51.100.9 drop") {
		t.Fatalf("expected the block rule to render even with IsolatePeers off, got:\n%s", out)
	}
}

func TestRulesetPortOnlyRuleMatchesBothProtocolsByDefault(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.8.0.0/24")
	out := Ruleset(FirewallSpec{
		WGSubnet: subnet,
		Rules:    []FirewallRule{{Action: "block", Port: 25}},
	})
	if !strings.Contains(out, "meta l4proto { tcp, udp } th dport 25 drop") {
		t.Fatalf("expected a protocol-agnostic port rule, got:\n%s", out)
	}
}

func TestRulesetProtocolSpecificPortRule(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.8.0.0/24")
	out := Ruleset(FirewallSpec{
		WGSubnet: subnet,
		Rules:    []FirewallRule{{Action: "allow", Port: 443, Protocol: "tcp"}},
	})
	if !strings.Contains(out, "tcp dport 443 accept") {
		t.Fatalf("expected a tcp-specific port rule, got:\n%s", out)
	}
	if strings.Contains(out, "udp dport 443") {
		t.Fatalf("a tcp-only rule must not also match udp, got:\n%s", out)
	}
}

func TestRulesetAddressAndPortCombinedRule(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.8.0.0/24")
	out := Ruleset(FirewallSpec{
		WGSubnet: subnet,
		Rules:    []FirewallRule{{Action: "block", Address: "10.8.0.50", Port: 22, Protocol: "tcp"}},
	})
	if !strings.Contains(out, "ip daddr 10.8.0.50 tcp dport 22 drop") {
		t.Fatalf("expected a combined address+port rule, got:\n%s", out)
	}
}

// TestRulesetRulesRenderInGivenOrder guards the "priority" promise: Rules
// must come out in the exact order they were given, since that order is
// what makes first-match-wins behave as the operator arranged it (e.g. an
// allow for one address inside a /24 that's otherwise blocked only works if
// it's rendered before the block).
func TestRulesetRulesRenderInGivenOrder(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.8.0.0/24")
	out := Ruleset(FirewallSpec{
		WGSubnet: subnet,
		Rules: []FirewallRule{
			{Action: "allow", Address: "10.8.0.5"},
			{Action: "block", Address: "10.8.0.0/24"},
		},
	})
	allowIdx := strings.Index(out, "ip daddr 10.8.0.5 accept")
	blockIdx := strings.Index(out, "ip daddr 10.8.0.0/24 drop")
	if allowIdx < 0 || blockIdx < 0 {
		t.Fatalf("expected both rules to render, got:\n%s", out)
	}
	if allowIdx > blockIdx {
		t.Fatalf("rules must render in the given order so the earlier one is evaluated first, got:\n%s", out)
	}
}

// TestRulesetFlushesBeforeRedeclaring guards against a real bug found in
// production: nft's declarative `table { chain { ... } }` syntax only ever
// *adds* the listed rules — re-feeding the same ruleset to an
// already-existing table appends a second copy of every rule rather than
// replacing them, since nft rules are identified by handle, not content.
// Every tenant restart/reconcile re-applies this ruleset, so without a
// flush the chain would grow by a full copy of itself every time.
func TestRulesetFlushesBeforeRedeclaring(t *testing.T) {
	_, subnet, _ := net.ParseCIDR("10.8.0.0/24")
	out := Ruleset(FirewallSpec{WGSubnet: subnet, IsolatePeers: true})
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 || lines[0] != "add table inet hazyvpn" || lines[1] != "flush table inet hazyvpn" {
		t.Fatalf("expected the ruleset to start with add+flush table statements, got:\n%s", out)
	}
}
