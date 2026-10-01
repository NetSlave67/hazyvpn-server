package main

import (
	"image/color"

	"charm.land/lipgloss/v2"
)

// Semantic color variables — ANSI terminal colors, set by initColors().
var (
	green     color.Color // up/active/success states
	red       color.Color // errors
	yellow    color.Color // warnings
	accent    color.Color // titles, active borders, highlights, shortcuts
	textCol   color.Color // primary text
	dimCol    color.Color // labels, inactive text, dim elements
	borderCol color.Color // panel borders, dividers
	base      color.Color // background
)

// Style variables — set by initStyles().
var (
	titleStyle        lipgloss.Style
	itemStyle         lipgloss.Style
	selectedNameStyle lipgloss.Style
	dimItemStyle      lipgloss.Style
	labelStyle        lipgloss.Style
	valueStyle        lipgloss.Style
	activeStyle       lipgloss.Style
	errorStyle        lipgloss.Style
	warnStyle         lipgloss.Style
	dimStyle          lipgloss.Style
	paneStyle         lipgloss.Style
	activePaneStyle   lipgloss.Style
	helpOverlayStyle  lipgloss.Style
	helpTitleStyle    lipgloss.Style
	inputPromptStyle  lipgloss.Style
	spinnerStyle      lipgloss.Style
	statusBarStyle    lipgloss.Style
)

func initStyles() {
	titleStyle = lipgloss.NewStyle().
		Foreground(accent).
		Bold(true)

	itemStyle = lipgloss.NewStyle().
		Foreground(textCol)

	selectedNameStyle = lipgloss.NewStyle().
		Foreground(accent).
		Bold(true)

	dimItemStyle = lipgloss.NewStyle().
		Foreground(dimCol)

	labelStyle = lipgloss.NewStyle().
		Foreground(dimCol).
		Width(15)

	valueStyle = lipgloss.NewStyle().
		Foreground(textCol)

	activeStyle = lipgloss.NewStyle().Foreground(green)
	errorStyle = lipgloss.NewStyle().Foreground(red)
	warnStyle = lipgloss.NewStyle().Foreground(yellow)
	dimStyle = lipgloss.NewStyle().Foreground(dimCol)

	paneStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderCol).
		Padding(0, 1)

	activePaneStyle = paneStyle.
		BorderForeground(accent)

	helpOverlayStyle = lipgloss.NewStyle().
		Border(lipgloss.RoundedBorder()).
		BorderForeground(borderCol).
		Padding(1, 2)

	helpTitleStyle = lipgloss.NewStyle().
		Foreground(textCol).
		Bold(true)

	inputPromptStyle = lipgloss.NewStyle().
		Foreground(accent)

	spinnerStyle = lipgloss.NewStyle().
		Foreground(accent)

	statusBarStyle = lipgloss.NewStyle().
		Foreground(dimCol)
}
