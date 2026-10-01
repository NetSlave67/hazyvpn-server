package netns

import (
	"fmt"
	"net"
	"strings"
	"testing"
)

// recordedCall captures one invocation made against the fake runner.
type recordedCall struct {
	name  string
	args  []string
	stdin string
}

// fakeRunner lets tests assert exactly which commands Manager issues, and
// inject a failure at a specific call index, without touching the real
// network stack.
type fakeRunner struct {
	calls   []recordedCall
	failAt  int // -1 means never fail
	failErr error
}

func newFakeRunner() *fakeRunner {
	return &fakeRunner{failAt: -1}
}

func (f *fakeRunner) Run(name string, args ...string) ([]byte, error) {
	return f.RunStdin(name, "", args...)
}

func (f *fakeRunner) RunStdin(name string, stdin string, args ...string) ([]byte, error) {
	f.calls = append(f.calls, recordedCall{name: name, args: args, stdin: stdin})
	if f.failAt == len(f.calls)-1 {
		return nil, f.failErr
	}
	return nil, nil
}

func TestCreateIssuesExpectedCommandSequence(t *testing.T) {
	fr := newFakeRunner()
	m := newManagerWithRunner(fr)

	if err := m.Create(7, "10.8.0.1/24"); err != nil {
		t.Fatalf("Create: %v", err)
	}

	joined := make([]string, len(fr.calls))
	for i, c := range fr.calls {
		joined[i] = c.name + " " + strings.Join(c.args, " ")
	}
	full := strings.Join(joined, "\n")

	for _, want := range []string{
		"ip netns add hazy-t7",
		"ip link add hveth7 type veth peer name veth0",
		"ip link set veth0 netns hazy-t7",
		"ip link add wg0 type wireguard",
		"ip addr add 10.8.0.1/24 dev wg0",
		"ip link set wg0 up",
	} {
		if !strings.Contains(full, want) {
			t.Fatalf("expected command sequence to contain %q, got:\n%s", want, full)
		}
	}
}

func TestCreateRollsBackOnFailure(t *testing.T) {
	fr := newFakeRunner()
	// Fail on the 3rd call (moving veth into the namespace).
	fr.failAt = 2
	fr.failErr = fmt.Errorf("boom")
	m := newManagerWithRunner(fr)

	err := m.Create(3, "10.8.0.1/24")
	if err == nil {
		t.Fatal("expected Create to return the injected error")
	}

	var sawDestroy bool
	for _, c := range fr.calls {
		if c.name == "ip" && len(c.args) >= 2 && c.args[0] == "netns" && c.args[1] == "del" {
			sawDestroy = true
		}
	}
	if !sawDestroy {
		t.Fatal("expected Create to roll back via Destroy after a mid-sequence failure")
	}
}

func TestDestroyIgnoresAlreadyGoneNamespace(t *testing.T) {
	fr := newFakeRunner()
	fr.failAt = 0
	fr.failErr = fmt.Errorf("Cannot remove namespace file \"/var/run/netns/hazy-t9\": No such file or directory")
	m := newManagerWithRunner(fr)

	if err := m.Destroy(9); err != nil {
		t.Fatalf("Destroy should tolerate an already-gone namespace, got: %v", err)
	}
}

func TestSyncWireGuardWritesConfigAndCallsSetconf(t *testing.T) {
	fr := newFakeRunner()
	m := newManagerWithRunner(fr)

	if err := m.SyncWireGuard(5, "[Interface]\nPrivateKey = abc\n"); err != nil {
		t.Fatalf("SyncWireGuard: %v", err)
	}
	last := fr.calls[len(fr.calls)-1]
	if last.name != "ip" || strings.Join(last.args[:4], " ") != "netns exec hazy-t5 wg" {
		t.Fatalf("unexpected call: %+v", last)
	}
	if last.args[4] != "setconf" || last.args[5] != "wg0" {
		t.Fatalf("expected 'wg setconf wg0 <path>', got args: %v", last.args)
	}
}

func TestExistsTrueWhenNamespaceReachable(t *testing.T) {
	fr := newFakeRunner()
	m := newManagerWithRunner(fr)

	exists, err := m.Exists(4)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if !exists {
		t.Fatal("expected Exists to be true when the probe command succeeds")
	}
}

func TestExistsFalseWhenNamespaceMissing(t *testing.T) {
	fr := newFakeRunner()
	fr.failAt = 0
	fr.failErr = fmt.Errorf(`Cannot open network namespace "hazy-t4": No such file or directory`)
	m := newManagerWithRunner(fr)

	exists, err := m.Exists(4)
	if err != nil {
		t.Fatalf("Exists: %v", err)
	}
	if exists {
		t.Fatal("expected Exists to be false for a missing namespace")
	}
}

func TestApplyFirewallFeedsRulesetViaStdin(t *testing.T) {
	fr := newFakeRunner()
	m := newManagerWithRunner(fr)

	_, subnet, _ := net.ParseCIDR("10.8.0.0/24")
	if err := m.ApplyFirewall(2, FirewallSpec{WGSubnet: subnet, IsolatePeers: true}); err != nil {
		t.Fatalf("ApplyFirewall: %v", err)
	}
	last := fr.calls[len(fr.calls)-1]
	if !strings.Contains(last.stdin, "policy drop") {
		t.Fatalf("expected ruleset to be piped via stdin, got: %q", last.stdin)
	}
	if strings.Join(last.args, " ") != "netns exec hazy-t2 nft -f -" {
		t.Fatalf("unexpected args: %v", last.args)
	}
}
