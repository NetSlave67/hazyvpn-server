package qrcode

import (
	"strings"
	"testing"
)

func TestPNGProducesValidHeader(t *testing.T) {
	png, err := PNG("hello world", 128)
	if err != nil {
		t.Fatalf("PNG: %v", err)
	}
	// PNG files start with an 8-byte magic signature.
	want := []byte{0x89, 'P', 'N', 'G', '\r', '\n', 0x1a, '\n'}
	if len(png) < len(want) {
		t.Fatalf("PNG output too short: %d bytes", len(png))
	}
	for i, b := range want {
		if png[i] != b {
			t.Fatalf("PNG magic byte %d = %x, want %x", i, png[i], b)
		}
	}
}

func TestTerminalRendersNonEmptyBlockArt(t *testing.T) {
	out, err := Terminal("[Interface]\nPrivateKey = abc\n")
	if err != nil {
		t.Fatalf("Terminal: %v", err)
	}
	lines := strings.Split(strings.TrimRight(out, "\n"), "\n")
	if len(lines) < 10 {
		t.Fatalf("expected a multi-line QR render, got %d lines", len(lines))
	}
	if !strings.ContainsAny(out, "█▀▄") {
		t.Fatal("expected block characters in terminal QR output")
	}
}
