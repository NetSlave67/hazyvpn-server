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
