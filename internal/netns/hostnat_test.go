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

func TestSyncHostPortForwardingRunsOnHostNotNamespace(t *testing.T) {
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
