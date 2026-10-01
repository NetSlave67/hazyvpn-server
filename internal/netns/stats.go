package netns

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// PeerStat is a road-warrior's live connection state, read straight from
// the kernel — never stored, always current as of the call.
type PeerStat struct {
	// LastHandshake is the zero Time if this peer has never completed a
	// handshake (wg reports this as unix timestamp 0).
	LastHandshake time.Time
	RxBytes       int64
	TxBytes       int64
}

// Connected reports whether this peer has a recent-enough handshake to be
// considered actively connected. WireGuard re-handshakes at least every 3
// minutes while a tunnel is active, so a peer silent much longer than that
// has either disconnected or never connected at all.
func (s PeerStat) Connected() bool {
	return !s.LastHandshake.IsZero() && time.Since(s.LastHandshake) < 3*time.Minute
}

// PeerStats returns live stats for every peer currently configured on a
// tenant's wg0 interface, keyed by public key. A peer with no entry in the
// map (rather than an error) simply hasn't been given to the kernel yet —
// callers should treat a missing key the same as PeerStat{}.
func (m *Manager) PeerStats(tenantID int64) (map[string]PeerStat, error) {
	ns := Namespace(tenantID)
	out, err := m.run.Run("ip", "netns", "exec", ns, "wg", "show", WGInterface, "dump")
	if err != nil {
		return nil, fmt.Errorf("netns: reading WireGuard stats: %w", err)
	}
	return parseWGDump(string(out)), nil
}

// parseWGDump parses `wg show <iface> dump` output. The first line
// describes the interface itself (private key, public key, listen port,
// fwmark) and is skipped; each following line is one peer:
//
//	public-key  preshared-key  endpoint  allowed-ips  latest-handshake  rx-bytes  tx-bytes  keepalive
func parseWGDump(out string) map[string]PeerStat {
	stats := make(map[string]PeerStat)
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	for i, line := range lines {
		if i == 0 || line == "" {
			continue // interface line, or trailing blank
		}
		fields := strings.Split(line, "\t")
		if len(fields) < 7 {
			continue // malformed/unexpected — skip rather than guess
		}
		pubKey := fields[0]
		handshakeUnix, _ := strconv.ParseInt(fields[4], 10, 64)
		rx, _ := strconv.ParseInt(fields[5], 10, 64)
		tx, _ := strconv.ParseInt(fields[6], 10, 64)

		var handshake time.Time
		if handshakeUnix > 0 {
			handshake = time.Unix(handshakeUnix, 0)
		}
		stats[pubKey] = PeerStat{LastHandshake: handshake, RxBytes: rx, TxBytes: tx}
	}
	return stats
}
