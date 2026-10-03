package main

import (
	"strings"

	"charm.land/bubbles/v2/textinput"
	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
)

// formField is one row of a form: either a text input or a yes/no toggle.
// Tenant and peer creation share this one implementation rather than each
// hand-rolling field navigation.
type formField struct {
	label     string
	help      string
	input     textinput.Model
	isToggle  bool
	toggleVal bool
}

// form is a small, generic multi-field input form rendered as a modal:
// tab/shift+tab move focus, space flips a toggle field, enter submits.
type form struct {
	title  string
	fields []formField
	focus  int
	errMsg string
}

func newForm(title string) *form {
	return &form{title: title}
}

func newTextField(label, help, value string) formField {
	ti := textinput.New()
	ti.Prompt = ""
	ti.CharLimit = 128
	ti.SetWidth(32)
	s := textinput.DefaultDarkStyles()
	s.Focused.Text = lipgloss.NewStyle().Foreground(textCol)
	s.Cursor.Color = accent
	ti.SetStyles(s)
	ti.SetValue(value)
	return formField{label: label, help: help, input: ti}
}

func (f *form) addText(label, help, value string) *form {
	f.fields = append(f.fields, newTextField(label, help, value))
	return f
}

func (f *form) addToggle(label, help string, value bool) *form {
	f.fields = append(f.fields, formField{label: label, help: help, isToggle: true, toggleVal: value})
	return f
}

// focusField blurs every field and focuses the one at f.focus.
func (f *form) focusField() {
	for i := range f.fields {
		if f.fields[i].isToggle {
			continue
		}
		if i == f.focus {
			f.fields[i].input.Focus()
		} else {
			f.fields[i].input.Blur()
		}
	}
}

func (f *form) value(label string) string {
	for _, field := range f.fields {
		if field.label == label {
			return strings.TrimSpace(field.input.Value())
		}
	}
	return ""
}

func (f *form) toggle(label string) bool {
	for _, field := range f.fields {
		if field.label == label {
			return field.toggleVal
		}
	}
	return false
}

// handleKey applies a keypress to the focused field and returns true if the
// form was submitted (enter on a non-empty form).
func (f *form) handleKey(msg tea.KeyPressMsg) (submitted bool, cmd tea.Cmd) {
	switch msg.String() {
	case "tab", "down":
		f.focus = (f.focus + 1) % len(f.fields)
		f.focusField()
		return false, nil
	case "shift+tab", "up":
		f.focus = (f.focus - 1 + len(f.fields)) % len(f.fields)
		f.focusField()
		return false, nil
	case "enter":
		return true, nil
	}

	cur := &f.fields[f.focus]
	if cur.isToggle {
		// bubbletea v2 renders the space bar's KeyPressMsg.String() as the
		// word "space", never a literal " " — Key.String() falls through to
		// Keystroke() whenever Text == " ", and Keystroke() writes "space"
		// for that key. Checking only " " here meant every toggle field in
		// this TUI (Preshared Key, Isolate Peers, and the newer firewall
		// rule Block toggle) could never actually be flipped by pressing
		// space; it went unnoticed because every toggle's chosen default
		// happened to be the value most users wanted anyway. Found live
		// while testing that the firewall rule form's Block toggle
		// wouldn't flip.
		if msg.String() == "space" || msg.String() == "left" || msg.String() == "right" {
			cur.toggleVal = !cur.toggleVal
		}
		return false, nil
	}
	var c tea.Cmd
	cur.input, c = cur.input.Update(msg)
	return false, c
}

func (f *form) View() string {
	var b strings.Builder
	b.WriteString(helpTitleStyle.Render(f.title))
	b.WriteString("\n\n")
	for i, field := range f.fields {
		marker := "  "
		if i == f.focus {
			marker = inputPromptStyle.Render("› ")
		}
		b.WriteString(marker)
		b.WriteString(labelStyle.Render(field.label))
		if field.isToggle {
			if field.toggleVal {
				b.WriteString(activeStyle.Render("[x] yes"))
			} else {
				b.WriteString(dimStyle.Render("[ ] no"))
			}
		} else {
			b.WriteString(field.input.View())
		}
		if field.help != "" {
			b.WriteString("  " + dimStyle.Render(field.help))
		}
		b.WriteString("\n")
	}
	if f.errMsg != "" {
		b.WriteString("\n")
		b.WriteString(errorStyle.Render(f.errMsg))
		b.WriteString("\n")
	}
	b.WriteString("\n")
	b.WriteString(dimStyle.Render("tab/shift+tab move · space toggle · enter submit · esc cancel"))
	return helpOverlayStyle.Render(b.String())
}
