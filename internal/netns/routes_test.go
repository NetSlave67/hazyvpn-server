package netns

import (
	"strings"
	"testing"
)

// countCalls returns how many recorded calls match verb (e.g. "add"/"del")
// on the given route destination.
func countCalls(calls []recordedCall, verb, dest string) int {
	n := 0
	for _, c := range calls {
		joined := strings.Join(c.args, " ")
		if strings.Contains(joined, "route "+verb+" "+dest) {
			n++
		}
	}
	return n
}

func TestSyncRoutedPrefixesAddsNewRoute(t *testing.T) {
	fr := newFakeRunner()
	fr.outputs = map[string][]byte{
		outputKey("ip", []string{"netns", "exec", "hazy-t1", "ip", "-4", "route", "show", "dev", "wg0"}): []byte("10.0.0.0/24 dev wg0 proto kernel scope link src 10.0.0.1\n"),
	}
	m := newManagerWithRunner(fr)

	if err := m.SyncRoutedPrefixes(1, "10.0.0.0/24", []string{"192.168.50.0/24"}); err != nil {
		t.Fatalf("SyncRoutedPrefixes: %v", err)
	}
	if countCalls(fr.calls, "add", "192.168.50.0/24") != 1 {
		t.Fatalf("expected exactly one add for the new route, calls: %+v", fr.calls)
	}
	if countCalls(fr.calls, "del", "10.0.0.0/24") != 0 {
		t.Fatal("the tenant's own connected subnet must never be deleted")
	}
}

func TestSyncRoutedPrefixesRemovesStaleRoute(t *testing.T) {
	fr := newFakeRunner()
	fr.outputs = map[string][]byte{
		outputKey("ip", []string{"netns", "exec", "hazy-t1", "ip", "-4", "route", "show", "dev", "wg0"}): []byte(
			"10.0.0.0/24 dev wg0 proto kernel scope link src 10.0.0.1\n" +
				"10.99.0.0/24 dev wg0 scope link\n"),
	}
	m := newManagerWithRunner(fr)

	// No prefixes desired anymore — 10.99.0.0/24 (left over from a prior
	// RoutedPrefixes value) must be removed.
	if err := m.SyncRoutedPrefixes(1, "10.0.0.0/24", nil); err != nil {
		t.Fatalf("SyncRoutedPrefixes: %v", err)
	}
	if countCalls(fr.calls, "del", "10.99.0.0/24") != 1 {
		t.Fatalf("expected the stale route to be removed, calls: %+v", fr.calls)
	}
	if countCalls(fr.calls, "del", "10.0.0.0/24") != 0 {
		t.Fatal("the tenant's own connected subnet must never be deleted")
	}
}

func TestSyncRoutedPrefixesIsIdempotent(t *testing.T) {
	fr := newFakeRunner()
	fr.outputs = map[string][]byte{
		outputKey("ip", []string{"netns", "exec", "hazy-t1", "ip", "-4", "route", "show", "dev", "wg0"}): []byte(
			"10.0.0.0/24 dev wg0 proto kernel scope link src 10.0.0.1\n" +
				"192.168.50.0/24 dev wg0 scope link\n"),
	}
	m := newManagerWithRunner(fr)

	if err := m.SyncRoutedPrefixes(1, "10.0.0.0/24", []string{"192.168.50.0/24"}); err != nil {
		t.Fatalf("SyncRoutedPrefixes: %v", err)
	}
	for _, c := range fr.calls {
		joined := strings.Join(c.args, " ")
		if strings.Contains(joined, "route add") || strings.Contains(joined, "route del") {
			t.Fatalf("expected no add/del calls when state already matches desired, got: %+v", c)
		}
	}
}

func TestSyncRoutedPrefixesRoutesIPv6Separately(t *testing.T) {
	fr := newFakeRunner()
	m := newManagerWithRunner(fr)

	if err := m.SyncRoutedPrefixes(1, "10.0.0.0/24", []string{"192.168.50.0/24", "fd00:50::/64"}); err != nil {
		t.Fatalf("SyncRoutedPrefixes: %v", err)
	}
	if countCalls(fr.calls, "add", "192.168.50.0/24") != 1 {
		t.Fatal("expected the IPv4 prefix to be added via `ip -4`")
	}
	if countCalls(fr.calls, "add", "fd00:50::/64") != 1 {
		t.Fatal("expected the IPv6 prefix to be added via `ip -6`")
	}
	var sawV6Add bool
	for _, c := range fr.calls {
		if strings.Contains(strings.Join(c.args, " "), "route add fd00:50::/64") {
			for _, a := range c.args {
				if a == "-6" {
					sawV6Add = true
				}
			}
		}
	}
	if !sawV6Add {
		t.Fatal("expected the IPv6 route add to use the -6 family flag")
	}
}

func TestIsIPv6CIDR(t *testing.T) {
	if isIPv6CIDR("10.0.0.0/24") {
		t.Fatal("10.0.0.0/24 is not IPv6")
	}
	if !isIPv6CIDR("fd00::/64") {
		t.Fatal("fd00::/64 is IPv6")
	}
}
