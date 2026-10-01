package main

import (
	"fmt"
	"strings"

	tea "charm.land/bubbletea/v2"
	"charm.land/lipgloss/v2"
	"hazyvpn-server/internal/store"
)

func (m model) View() tea.View {
	v := tea.NewView(m.render())
	v.AltScreen = true
	return v
}

func (m model) render() string {
	if m.width == 0 {
		return "loading…"
	}

	switch m.modal {
	case modalHelp:
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, m.helpView())
	case modalTenantForm, modalPeerForm:
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, m.withSpinner(m.form.View()))
	case modalPromptEmail, modalPromptImportPeer, modalPromptImportTenant, modalPromptExceptions:
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, m.withSpinner(m.prompt.View()))
	case modalConfirmDeleteTenant:
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, m.confirmView(
			fmt.Sprintf("Delete tenant %q and all of its peers? This cannot be undone.", tenantNameOr(m.selectedTenant(), "?"))))
	case modalConfirmDeletePeer:
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, m.confirmView(
			fmt.Sprintf("Remove peer %q?", peerNameOr(m.selectedPeer(), "?"))))
	case modalViewText:
		return lipgloss.Place(m.width, m.height, lipgloss.Center, lipgloss.Center, m.viewTextModal())
	}

	return m.dashboardView()
}

func tenantNameOr(t *store.Tenant, fallback string) string {
	if t == nil {
		return fallback
	}
	return t.Name
}

func peerNameOr(p *store.Peer, fallback string) string {
	if p == nil {
		return fallback
	}
	return p.Name
}

func (m model) withSpinner(content string) string {
	if !m.busy {
		return content
	}
	return content + "\n\n" + spinnerStyle.Render(m.spin.View()+" working…")
}

func (m model) confirmView(prompt string) string {
	body := prompt + "\n\n" + dimStyle.Render("y confirm · n/esc cancel")
	return helpOverlayStyle.Render(body)
}

func (m model) helpView() string {
	var b strings.Builder
	b.WriteString(helpTitleStyle.Render("HazyVPN Server — Help"))
	b.WriteString("\n\n")
	for _, group := range m.keys.FullHelp() {
		var parts []string
		for _, kb := range group {
			parts = append(parts, inputPromptStyle.Render(kb.Help().Key)+" "+dimStyle.Render(kb.Help().Desc))
		}
		b.WriteString(strings.Join(parts, "    "))
		b.WriteString("\n")
	}
	b.WriteString("\n" + dimStyle.Render("any key closes this"))
	return helpOverlayStyle.Render(b.String())
}

func (m model) viewTextModal() string {
	title := helpTitleStyle.Render(m.viewKind)
	body := title + "\n\n" + m.viewText + "\n" + dimStyle.Render("any key closes this")
	return helpOverlayStyle.Render(body)
}

func (m model) dashboardView() string {
	header := m.headerView()
	paneHeight := max(6, m.height-7)
	left := m.tenantsPane(paneHeight)
	right := m.peersPane(paneHeight)
	body := lipgloss.JoinHorizontal(lipgloss.Top, left, " ", right)
	footer := m.footerView()
	return lipgloss.JoinVertical(lipgloss.Left, header, body, footer)
}

func (m model) headerView() string {
	title := titleStyle.Render("HazyVPN Server")
	sub := dimStyle.Render(fmt.Sprintf("%d tenant(s)", len(m.tenants)))
	rx, tx := m.overallTraffic()
	traffic := dimStyle.Render(fmt.Sprintf("↓ %s  ↑ %s", formatBytes(rx), formatBytes(tx)))
	return title + "  " + sub + "  " + traffic + "\n"
}

func (m model) tenantsPane(height int) string {
	width := max(24, m.width/2-2)
	var b strings.Builder
	b.WriteString(helpTitleStyle.Render("Tenants"))
	b.WriteString("\n\n")
	if len(m.tenants) == 0 {
		b.WriteString(dimStyle.Render("No tenants yet — press n to create one.\n"))
	}
	for i, t := range m.tenants {
		line := fmt.Sprintf("%s · %s · :%d", t.Name, t.Subnet, t.ListenPort)
		if t.Enabled {
			rx, tx := m.tenantTraffic(t.ID)
			line += fmt.Sprintf(" · ↓%s ↑%s", formatBytes(rx), formatBytes(tx))
		} else {
			line += " · disabled"
		}
		if i == m.tenantCursor {
			if m.pane == paneTenants {
				b.WriteString(inputPromptStyle.Render("› ") + selectedNameStyle.Render(line) + "\n")
			} else {
				b.WriteString(dimStyle.Render("› ") + inactiveSelectedStyle.Render(line) + "\n")
			}
		} else if !t.Enabled {
			b.WriteString("  " + dimStyle.Render(line) + "\n")
		} else {
			b.WriteString("  " + itemStyle.Render(line) + "\n")
		}
	}
	style := paneStyle
	if m.pane == paneTenants {
		style = activePaneStyle
	}
	return style.Width(width).Height(height).Render(b.String())
}

func (m model) peersPane(height int) string {
	width := max(24, m.width/2-2)
	var b strings.Builder
	t := m.selectedTenant()
	if t == nil {
		b.WriteString(helpTitleStyle.Render("Peers"))
		b.WriteString("\n\n")
		b.WriteString(dimStyle.Render("Select a tenant to see its peers.\n"))
	} else {
		b.WriteString(helpTitleStyle.Render("Peers — " + t.Name))
		b.WriteString("\n\n")
		if len(m.peers) == 0 {
			b.WriteString(dimStyle.Render("No peers yet — press a to add one.\n"))
		}
		stats := m.allStats[t.ID]
		for i, p := range m.peers {
			dot := dimStyle.Render("○")
			handshake := "never"
			traffic := ""
			if p.Enabled {
				if stat, ok := stats[p.PublicKey]; ok {
					handshake = formatHandshake(stat.LastHandshake)
					if stat.Connected() {
						dot = activeStyle.Render("●")
					}
					if stat.RxBytes > 0 || stat.TxBytes > 0 {
						traffic = fmt.Sprintf(" · ↓%s ↑%s", formatBytes(stat.RxBytes), formatBytes(stat.TxBytes))
					}
				}
			} else {
				handshake = "disabled"
			}
			line := fmt.Sprintf("%s %s · %s · %s%s", dot, p.Name, p.Address, handshake, traffic)
			switch {
			case i == m.peerCursor && m.pane == panePeers:
				b.WriteString(inputPromptStyle.Render("› ") + selectedNameStyle.Render(line) + "\n")
			case i == m.peerCursor:
				b.WriteString(dimStyle.Render("› ") + inactiveSelectedStyle.Render(line) + "\n")
			case !p.Enabled:
				b.WriteString("  " + dimStyle.Render(line) + "\n")
			default:
				b.WriteString("  " + itemStyle.Render(line) + "\n")
			}
		}
	}
	style := paneStyle
	if m.pane == panePeers {
		style = activePaneStyle
	}
	return style.Width(width).Height(height).Render(b.String())
}

func (m model) footerView() string {
	hints := renderKeyFooter(m.help, m.keys.ShortHelp(), m.width)
	if m.message != "" {
		return hints + "\n" + m.message
	}
	return hints
}
