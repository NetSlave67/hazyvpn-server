package main

import (
	"testing"
	"time"
)

func TestFormatHandshakeNever(t *testing.T) {
	if got := formatHandshake(time.Time{}); got != "never" {
		t.Fatalf("formatHandshake(zero) = %q, want never", got)
	}
}

func TestFormatHandshakeRelative(t *testing.T) {
	cases := []struct {
		ago  time.Duration
		want string
	}{
		{10 * time.Second, "just now"},
		{90 * time.Second, "1m ago"},
		{2 * time.Hour, "2h ago"},
		{49 * time.Hour, "2d ago"},
	}
	for _, c := range cases {
		got := formatHandshake(time.Now().Add(-c.ago))
		if got != c.want {
			t.Errorf("formatHandshake(%v ago) = %q, want %q", c.ago, got, c.want)
		}
	}
}

func TestFormatBytes(t *testing.T) {
	cases := []struct {
		n    int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1024, "1.0 KiB"},
		{1536, "1.5 KiB"},
		{1 << 20, "1.0 MiB"},
		{1 << 30, "1.0 GiB"},
	}
	for _, c := range cases {
		if got := formatBytes(c.n); got != c.want {
			t.Errorf("formatBytes(%d) = %q, want %q", c.n, got, c.want)
		}
	}
}
