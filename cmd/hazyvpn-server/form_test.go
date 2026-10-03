package main

import (
	"testing"

	tea "charm.land/bubbletea/v2"
)

// spaceKey builds the KeyPressMsg bubbletea v2 actually sends for the space
// bar. Its Code is the space rune and, since that's a printable character,
// Text is populated too.
func spaceKey() tea.KeyPressMsg {
	return tea.KeyPressMsg{Code: ' ', Text: " "}
}

// TestFormToggleFlipsOnSpace guards a real bug found live: bubbletea v2's
// KeyPressMsg.String() renders the space bar as the word "space", not a
// literal " " character (Key.String() falls through to Keystroke(), which
// special-cases KeySpace to write "space") — so comparing msg.String() == " "
// never matches, and a toggle field could never actually be flipped from the
// keyboard. It went unnoticed for every existing toggle (Preshared Key,
// Isolate Peers) because their true defaults happened to be what most
// operators wanted; it became visible once the firewall rule form's "Block"
// toggle defaulted to false and needed to be flippable to true.
func TestFormToggleFlipsOnSpace(t *testing.T) {
	f := newForm("Test")
	f.addToggle("Block", "", false)
	f.focusField()

	if f.toggle("Block") {
		t.Fatal("expected the toggle to start false")
	}
	if submitted, _ := f.handleKey(spaceKey()); submitted {
		t.Fatal("space must not submit the form")
	}
	if !f.toggle("Block") {
		t.Fatal("expected space to flip the toggle to true")
	}
	if _, _ = f.handleKey(spaceKey()); f.toggle("Block") {
		t.Fatal("expected a second space press to flip the toggle back to false")
	}
}

func TestFormToggleFlipsOnArrowKeys(t *testing.T) {
	f := newForm("Test")
	f.addToggle("Block", "", false)
	f.focusField()

	if _, _ = f.handleKey(tea.KeyPressMsg{Code: tea.KeyLeft}); !f.toggle("Block") {
		t.Fatal("expected left arrow to flip the toggle")
	}
	if _, _ = f.handleKey(tea.KeyPressMsg{Code: tea.KeyRight}); f.toggle("Block") {
		t.Fatal("expected right arrow to flip the toggle back")
	}
}
