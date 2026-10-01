package netns

import (
	"testing"
	"time"
)

const sampleDump = "cEhBpuZuKkIkbaw1xMkXz4jfM+2KrTl4p5LWIPgAfxQ=\tKHjlsaJBBQNz1iHB05Sc1LNyGDla9Gl4MU9yrC4usxs=\t51820\toff\n" +
	"LNJocGm9Tv2cM4WLBFIxhEzhAjWxo2hie1fU7JK6HUs=\t(none)\t203.0.113.5:51000\t10.0.0.2/32\t1700000000\t1024\t2048\toff\n" +
	"FqZlWhibQj2c8V1QavBdlQQHXEkakOxmAFR2itw8m2k=\t(none)\t(none)\t10.0.0.3/32\t0\t0\t0\toff\n"

func TestParseWGDumpSkipsInterfaceLine(t *testing.T) {
	stats := parseWGDump(sampleDump)
	if len(stats) != 2 {
		t.Fatalf("expected 2 peers, got %d: %+v", len(stats), stats)
	}
}

func TestParseWGDumpHandshakeAndTransfer(t *testing.T) {
	stats := parseWGDump(sampleDump)
	connected := stats["LNJocGm9Tv2cM4WLBFIxhEzhAjWxo2hie1fU7JK6HUs="]
	if connected.LastHandshake.IsZero() {
		t.Fatal("expected a non-zero handshake time for the connected peer")
	}
	if connected.RxBytes != 1024 || connected.TxBytes != 2048 {
		t.Fatalf("RxBytes/TxBytes = %d/%d, want 1024/2048", connected.RxBytes, connected.TxBytes)
	}
}

func TestParseWGDumpNeverHandshaked(t *testing.T) {
	stats := parseWGDump(sampleDump)
	never := stats["FqZlWhibQj2c8V1QavBdlQQHXEkakOxmAFR2itw8m2k="]
	if !never.LastHandshake.IsZero() {
		t.Fatalf("expected zero handshake time for a peer that never connected, got %v", never.LastHandshake)
	}
	if never.Connected() {
		t.Fatal("a peer with no handshake must not report as Connected")
	}
}

func TestPeerStatConnectedWindow(t *testing.T) {
	recent := PeerStat{LastHandshake: time.Now().Add(-30 * time.Second)}
	if !recent.Connected() {
		t.Fatal("a handshake 30s ago should count as connected")
	}
	stale := PeerStat{LastHandshake: time.Now().Add(-10 * time.Minute)}
	if stale.Connected() {
		t.Fatal("a handshake 10 minutes ago should not count as connected")
	}
	never := PeerStat{}
	if never.Connected() {
		t.Fatal("the zero value must not report as Connected")
	}
}

func TestPeerStatsRunsWgShowDumpInNamespace(t *testing.T) {
	fr := newFakeRunner()
	m := newManagerWithRunner(fr)

	if _, err := m.PeerStats(7); err != nil {
		t.Fatalf("PeerStats: %v", err)
	}
	last := fr.calls[len(fr.calls)-1]
	gotArgs := last.args
	wantArgs := []string{"netns", "exec", "hazy-t7", "wg", "show", "wg0", "dump"}
	if len(gotArgs) != len(wantArgs) {
		t.Fatalf("args = %v, want %v", gotArgs, wantArgs)
	}
	for i := range wantArgs {
		if gotArgs[i] != wantArgs[i] {
			t.Fatalf("args = %v, want %v", gotArgs, wantArgs)
		}
	}
}
