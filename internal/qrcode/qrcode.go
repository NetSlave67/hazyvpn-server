// Package qrcode renders a peer's WireGuard config as a QR code, either as
// PNG bytes (for email/export) or as ANSI block text (for display directly
// in the TUI) — generated on demand, never persisted unless explicitly
// exported.
package qrcode

import (
	"fmt"
	"strings"

	"github.com/skip2/go-qrcode"
)

// PNG renders config as a QR code PNG image at the given pixel size (e.g.
// 256), suitable for emailing or writing to disk.
func PNG(config string, size int) ([]byte, error) {
	png, err := qrcode.Encode(config, qrcode.Medium, size)
	if err != nil {
		return nil, fmt.Errorf("qrcode: encoding PNG: %w", err)
	}
	return png, nil
}

// Terminal renders config as a QR code using two half-block characters per
// cell so it displays at roughly the right aspect ratio in a terminal.
func Terminal(config string) (string, error) {
	q, err := qrcode.New(config, qrcode.Medium)
	if err != nil {
		return "", fmt.Errorf("qrcode: encoding terminal QR: %w", err)
	}
	// Bitmap() modules are false=dark, true=light (see go-qrcode's own
	// symbol.string() rendering) and already include the spec's quiet zone.
	bitmap := q.Bitmap()

	var b strings.Builder
	height := len(bitmap)
	for y := 0; y < height; y += 2 {
		for x := 0; x < len(bitmap[y]); x++ {
			top := isDark(bitmap, x, y)
			bottom := isDark(bitmap, x, y+1)
			b.WriteRune(halfBlock(top, bottom))
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func isDark(bitmap [][]bool, x, y int) bool {
	if y < 0 || y >= len(bitmap) || x < 0 || x >= len(bitmap[y]) {
		return false // out of bounds (odd final row) reads as light
	}
	return !bitmap[y][x]
}

// halfBlock picks the Unicode block character representing a dark/light pair
// stacked vertically, so one terminal character cell encodes two QR modules.
func halfBlock(topDark, bottomDark bool) rune {
	switch {
	case topDark && bottomDark:
		return '█'
	case topDark && !bottomDark:
		return '▀'
	case !topDark && bottomDark:
		return '▄'
	default:
		return ' '
	}
}
