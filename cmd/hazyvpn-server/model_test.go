package main

import (
	"testing"
	"time"

	"hazyvpn-server/internal/netns"
)

func TestTenantRateComputesDeltaOverElapsed(t *testing.T) {
	now := time.Now()
	m := model{
		prevStatsAt: now,
		statsAt:     now.Add(2 * time.Second),
		prevStats: map[int64]map[string]netns.PeerStat{
			1: {"peerA": {RxBytes: 1000, TxBytes: 500}},
		},
		allStats: map[int64]map[string]netns.PeerStat{
			1: {"peerA": {RxBytes: 3000, TxBytes: 1500}},
		},
	}
	rx, tx := m.tenantRate(1)
	if rx != 1000 { // (3000-1000) bytes / 2s = 1000 B/s
		t.Fatalf("rx rate = %v, want 1000", rx)
	}
	if tx != 500 { // (1500-500) / 2s = 500 B/s
		t.Fatalf("tx rate = %v, want 500", tx)
	}
}

func TestTenantRateZeroWithNoPreviousSnapshot(t *testing.T) {
	m := model{
		allStats: map[int64]map[string]netns.PeerStat{
			1: {"peerA": {RxBytes: 3000, TxBytes: 1500}},
		},
	}
	rx, tx := m.tenantRate(1)
	if rx != 0 || tx != 0 {
		t.Fatalf("rate with no previous sample = (%v, %v), want (0, 0)", rx, tx)
	}
}

func TestTenantRateIgnoresNewPeerWithNoPriorSample(t *testing.T) {
	now := time.Now()
	m := model{
		prevStatsAt: now,
		statsAt:     now.Add(1 * time.Second),
		prevStats:   map[int64]map[string]netns.PeerStat{1: {}},
		allStats: map[int64]map[string]netns.PeerStat{
			1: {"brandNew": {RxBytes: 50_000, TxBytes: 50_000}},
		},
	}
	rx, tx := m.tenantRate(1)
	if rx != 0 || tx != 0 {
		t.Fatalf("a peer absent from the previous sample must not count as a rate spike, got (%v, %v)", rx, tx)
	}
}

func TestTenantRateClampsCounterReset(t *testing.T) {
	// A tenant disable/re-enable (or any interface recreation) resets the
	// kernel's own counters to zero — a lower current count than the
	// previous sample must never be read as negative traffic.
	now := time.Now()
	m := model{
		prevStatsAt: now,
		statsAt:     now.Add(1 * time.Second),
		prevStats: map[int64]map[string]netns.PeerStat{
			1: {"peerA": {RxBytes: 5000, TxBytes: 5000}},
		},
		allStats: map[int64]map[string]netns.PeerStat{
			1: {"peerA": {RxBytes: 100, TxBytes: 100}},
		},
	}
	rx, tx := m.tenantRate(1)
	if rx != 0 || tx != 0 {
		t.Fatalf("a counter reset must clamp to 0, not go negative, got (%v, %v)", rx, tx)
	}
}

func TestOverallRateSumsAcrossTenants(t *testing.T) {
	now := time.Now()
	m := model{
		prevStatsAt: now,
		statsAt:     now.Add(1 * time.Second),
		prevStats: map[int64]map[string]netns.PeerStat{
			1: {"a": {RxBytes: 0}},
			2: {"b": {RxBytes: 0}},
		},
		allStats: map[int64]map[string]netns.PeerStat{
			1: {"a": {RxBytes: 100}},
			2: {"b": {RxBytes: 200}},
		},
	}
	rx, _ := m.overallRate()
	if rx != 300 {
		t.Fatalf("overallRate rx = %v, want 300 (100 + 200)", rx)
	}
}
