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
	case modalPromptEmail, modalPromptImportPeer, modalPromptImportTenant:
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
	return title + "  " + sub + "\n"
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
		if i == m.tenantCursor {
			marker := "› "
			if m.pane == paneTenants {
				marker = inputPromptStyle.Render("› ")
			} else {
				marker = dimStyle.Render("› ")
			}
			b.WriteString(marker + selectedNameStyle.Render(line) + "\n")
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
		for i, p := range m.peers {
			key := p.PublicKey
			if len(key) > 12 {
				key = key[:12] + "…"
			}
			line := fmt.Sprintf("%s · %s · %s", p.Name, p.Address, key)
			if i == m.peerCursor {
				marker := dimStyle.Render("› ")
				if m.pane == panePeers {
					marker = inputPromptStyle.Render("› ")
				}
				b.WriteString(marker + selectedNameStyle.Render(line) + "\n")
			} else {
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
