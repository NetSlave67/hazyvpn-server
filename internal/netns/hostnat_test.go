package netns

import (
	"strings"
	"testing"
)

func TestHostRulesetDNATsEachTenantPort(t *testing.T) {
	out, err := HostRuleset([]HostTenantPort{
		{TenantID: 1, ListenPort: 51001},
		{TenantID: 2, ListenPort: 51002},
	})
	if err != nil {
		t.Fatalf("HostRuleset: %v", err)
	}
	if !strings.Contains(out, "udp dport 51001 dnat to") {
		t.Fatal("expected a DNAT rule for tenant 1's port")
	}
	if !strings.Contains(out, "udp dport 51002 dnat to") {
		t.Fatal("expected a DNAT rule for tenant 2's port")
	}
	if strings.Contains(out, "policy drop") {
		t.Fatal("host ruleset must never set a drop policy — it would interfere with Docker's own rules")
	}
}

// TestHostRulesetMasqueradesLinkRangeForInternetEgress guards a real bug
// found live: a client with a full-tunnel AllowedIPs (0.0.0.0/0) could
// reach its tenant's own gateway but nothing beyond it — traceroute died
// exactly at the link-local address the tenant's own namespace MASQUERADEs
// to (see Ruleset's postrouting chain) because nothing then re-NATted that
// address before it left the container's own namespace via Docker's
// bridge. Docker's own NAT only covers its bridge subnet, not this
// link-local range, so this table has to do it.
func TestHostRulesetMasqueradesLinkRangeForInternetEgress(t *testing.T) {
	out, err := HostRuleset([]HostTenantPort{{TenantID: 1, ListenPort: 51001}})
	if err != nil {
		t.Fatalf("HostRuleset: %v", err)
	}
	if !strings.Contains(out, "ip saddr 169.254.0.0/16 masquerade") {
		t.Fatalf("expected a masquerade rule for the link-local range, got:\n%s", out)
	}
}

func TestHostRulesetMasqueradesEvenWithNoTenants(t *testing.T) {
	out, err := HostRuleset(nil)
	if err != nil {
		t.Fatalf("HostRuleset: %v", err)
	}
	if !strings.Contains(out, "masquerade") {
		t.Fatal("the masquerade rule should not depend on there being any tenants")
	}
}

// TestSyncHostPortForwardingRunsWithoutNetnsExec confirms this table is
// applied directly (no `ip netns exec <ns>` prefix) — i.e. inside whatever
// namespace this process itself is already running in, not a nested tenant
// namespace. See HostRuleset's doc comment for exactly which namespace that
// turns out to be in the Docker deployment this targets.
func TestSyncHostPortForwardingRunsWithoutNetnsExec(t *testing.T) {
	fr := newFakeRunner()
	m := newManagerWithRunner(fr)

	if err := m.SyncHostPortForwarding([]HostTenantPort{{TenantID: 1, ListenPort: 51001}}); err != nil {
		t.Fatalf("SyncHostPortForwarding: %v", err)
	}
	last := fr.calls[len(fr.calls)-1]
	if last.name != "nft" || strings.Join(last.args, " ") != "-f -" {
		t.Fatalf("expected a direct `nft -f -` call (no netns exec), got: %+v", last)
	}
	if !strings.Contains(last.stdin, "51001") {
		t.Fatalf("expected ruleset piped via stdin to mention the tenant's port, got: %q", last.stdin)
	}
}

// TestHostRulesetFlushesBeforeRedeclaring is the HostRuleset counterpart to
// firewall_test.go's TestRulesetFlushesBeforeRedeclaring — see that test's
// comment for why this matters. This table is the one where the bug it
// guards against actually bit: a tenant restored under a new name reusing
// an in-use listen port left two coexisting DNAT rules for the same port.
func TestHostRulesetFlushesBeforeRedeclaring(t *testing.T) {
	out, err := HostRuleset([]HostTenantPort{{TenantID: 1, ListenPort: 51001}})
	if err != nil {
		t.Fatalf("HostRuleset: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) < 2 || lines[0] != "add table ip hazyvpn_host" || lines[1] != "flush table ip hazyvpn_host" {
		t.Fatalf("expected the ruleset to start with add+flush table statements, got:\n%s", out)
	}
}
