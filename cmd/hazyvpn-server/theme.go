package main

import "charm.land/lipgloss/v2"

// initColors sets semantic color variables to ANSI terminal colors, so the
// terminal emulator's active theme drives the palette — same convention as
// the client-side hazyvpn TUI.
func initColors() {
	green = lipgloss.ANSIColor(2)
	red = lipgloss.ANSIColor(1)
	yellow = lipgloss.ANSIColor(3)
	accent = lipgloss.ANSIColor(4)
	textCol = lipgloss.ANSIColor(7)
	dimCol = lipgloss.ANSIColor(8)
	borderCol = lipgloss.ANSIColor(7)
	base = lipgloss.ANSIColor(0)

	initStyles()
}
