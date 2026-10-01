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
