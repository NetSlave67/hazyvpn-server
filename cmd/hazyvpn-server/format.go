package main

import (
	"fmt"
	"time"
)

// formatHandshake renders a peer's last handshake time as a short relative
// string, or "never" if it has never completed one.
func formatHandshake(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 24*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	default:
		return fmt.Sprintf("%dd ago", int(d.Hours()/24))
	}
}

// formatBytes renders a byte count in the largest unit that keeps it
// readable at a glance — good enough for a status line, not a precision
// instrument.
func formatBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for v := n / unit; v >= unit; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// formatBitrate renders a bytes-per-second rate as a human bitrate
// (bits/sec, decimal-scaled — standard networking convention, unlike the
// binary KiB/MiB used for cumulative byte counts in formatBytes).
func formatBitrate(bytesPerSec float64) string {
	bps := bytesPerSec * 8
	units := [...]string{"bps", "Kbps", "Mbps", "Gbps", "Tbps"}
	i := 0
	for bps >= 1000 && i < len(units)-1 {
		bps /= 1000
		i++
	}
	if i == 0 {
		return fmt.Sprintf("%.0f %s", bps, units[i])
	}
	return fmt.Sprintf("%.1f %s", bps, units[i])
}
