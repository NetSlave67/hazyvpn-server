package main

import (
	"time"

	"charm.land/bubbles/v2/key"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"
)

const messageTTL = 4 * time.Second

func (m model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		m.help.SetWidth(msg.Width)
		return m, nil

	case spinner.TickMsg:
		if !m.busy {
			return m, nil
		}
		var cmd tea.Cmd
		m.spin, cmd = m.spin.Update(msg)
		return m, cmd

	case clearMessageMsg:
		m.message = ""
		return m, nil

	case statsTickMsg:
		return m, tea.Batch(fetchAllStats(m.svc), statsTick())

	case allStatsMsg:
		if msg.err == nil {
			m.prevStats, m.prevStatsAt = m.allStats, m.statsAt
			m.allStats, m.statsAt = msg.stats, time.Now()
		}
		return m, nil

	case toggleTenantEnabledMsg:
		m.busy = false
		if msg.err != nil {
			m.setMessage(errorStyle.Render("Could not change tenant state: " + msg.err.Error()))
			return m, clearMessageAfter(messageTTL)
		}
		m.setMessage(activeStyle.Render("Tenant state updated"))
		return m, tea.Batch(loadTenants(m.svc), clearMessageAfter(messageTTL))

	case togglePeerEnabledMsg:
		m.busy = false
		if msg.err != nil {
			m.setMessage(errorStyle.Render("Could not change peer state: " + msg.err.Error()))
			return m, clearMessageAfter(messageTTL)
		}
		m.setMessage(activeStyle.Render("Peer state updated"))
		if t := m.selectedTenant(); t != nil {
			return m, tea.Batch(loadPeers(m.svc, t.ID), clearMessageAfter(messageTTL))
		}
		return m, clearMessageAfter(messageTTL)

	case peerRoutingUpdatedMsg:
		m.busy = false
		if msg.err != nil {
			m.setMessage(errorStyle.Render("Could not update routing: " + msg.err.Error()))
			return m, clearMessageAfter(messageTTL)
		}
		m.setMessage(activeStyle.Render("Peer routing updated"))
		if t := m.selectedTenant(); t != nil {
			return m, tea.Batch(loadPeers(m.svc, t.ID), clearMessageAfter(messageTTL))
		}
		return m, clearMessageAfter(messageTTL)

	case tenantsLoadedMsg:
		return m.onTenantsLoaded(msg)
	case peersLoadedMsg:
		return m.onPeersLoaded(msg)
	case tenantDefaultsMsg:
		return m.onTenantDefaults(msg)
	case peerDefaultsMsg:
		return m.onPeerDefaults(msg)
	case tenantCreatedMsg:
		return m.onTenantCreated(msg)
	case tenantDeletedMsg:
		return m.onTenantDeleted(msg)
	case peerAddedMsg:
		return m.onPeerAdded(msg)
	case peerDeletedMsg:
		return m.onPeerDeleted(msg)
	case configTextMsg:
		return m.onConfigText(msg)
	case qrReadyMsg:
		return m.onQRReady(msg)
	case firewallRulesLoadedMsg:
		return m.onFirewallRulesLoaded(msg)
	case firewallRuleAddedMsg:
		return m.onFirewallRuleAdded(msg)
	case firewallRuleDeletedMsg:
		return m.onFirewallRuleDeleted(msg)
	case firewallRuleMovedMsg:
		return m.onFirewallRuleMoved(msg)
	case emailSentMsg:
		m.busy = false
		if msg.err != nil {
			m.setMessage(errorStyle.Render("Email failed: " + msg.err.Error()))
		} else {
			m.setMessage(activeStyle.Render("Emailed config to " + msg.to))
		}
		return m, clearMessageAfter(messageTTL)
	case exportedMsg:
		m.busy = false
		if msg.err != nil {
			m.setMessage(errorStyle.Render("Export failed: " + msg.err.Error()))
		} else {
			m.setMessage(activeStyle.Render("Exported to " + msg.path))
		}
		return m, clearMessageAfter(messageTTL)
	case importedPeerMsg:
		m.busy = false
		if msg.err != nil {
			m.setMessage(errorStyle.Render("Import failed: " + msg.err.Error()))
			return m, clearMessageAfter(messageTTL)
		}
		m.setMessage(activeStyle.Render("Imported peer " + msg.name))
		if t := m.selectedTenant(); t != nil {
			return m, tea.Batch(loadPeers(m.svc, t.ID), clearMessageAfter(messageTTL))
		}
		return m, clearMessageAfter(messageTTL)
	case importedTenantMsg:
		m.busy = false
		if msg.err != nil {
			m.setMessage(errorStyle.Render("Import failed: " + msg.err.Error()))
			return m, clearMessageAfter(messageTTL)
		}
		m.setMessage(activeStyle.Render("Imported tenant " + msg.name))
		return m, tea.Batch(loadTenants(m.svc), clearMessageAfter(messageTTL))
	case clipboardCopiedMsg:
		m.busy = false
		if msg.err != nil {
			m.setMessage(errorStyle.Render("Clipboard unavailable: " + msg.err.Error()))
		} else {
			m.setMessage(activeStyle.Render("Copied config to clipboard"))
		}
		return m, clearMessageAfter(messageTTL)

	case tea.KeyPressMsg:
		if msg.String() == "ctrl+c" {
			return m, tea.Quit
		}
		if m.busy {
			return m, nil
		}
		return m.handleKey(msg)
	}
	return m, nil
}

func (m model) handleKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch m.modal {
	case modalHelp:
		m.modal = modalNone
		return m, nil
	case modalTenantForm:
		return m.updateTenantForm(msg)
	case modalPeerForm:
		return m.updatePeerForm(msg)
	case modalConfirmDeleteTenant:
		return m.updateConfirmDeleteTenant(msg)
	case modalConfirmDeletePeer:
		return m.updateConfirmDeletePeer(msg)
	case modalViewText:
		m.modal = modalNone
		return m, nil
	case modalPromptEmail, modalPromptImportPeer, modalPromptImportTenant, modalPromptRouting:
		return m.updatePrompt(msg)
	case modalFirewallRules:
		return m.updateFirewallRules(msg)
	case modalFirewallRuleForm:
		return m.updateFirewallRuleForm(msg)
	case modalConfirmDeleteFirewallRule:
		return m.updateConfirmDeleteFirewallRule(msg)
	}
	return m.handleNormalKey(msg)
}

func (m model) handleNormalKey(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	switch {
	case key.Matches(msg, m.keys.Quit):
		return m, tea.Quit
	case key.Matches(msg, m.keys.Help):
		m.modal = modalHelp
		return m, nil
	case key.Matches(msg, m.keys.Tab):
		if m.pane == paneTenants {
			m.pane = panePeers
		} else {
			m.pane = paneTenants
		}
		return m, nil
	case key.Matches(msg, m.keys.Up):
		return m.moveCursor(-1)
	case key.Matches(msg, m.keys.Down):
		return m.moveCursor(1)
	case key.Matches(msg, m.keys.NewTenant):
		m.busy = true
		return m, tea.Batch(suggestTenantDefaults(m.svc), m.spin.Tick)
	case key.Matches(msg, m.keys.NewPeer):
		t := m.selectedTenant()
		if t == nil {
			m.setMessage(warnStyle.Render("Select a tenant first"))
			return m, clearMessageAfter(messageTTL)
		}
		m.busy = true
		return m, tea.Batch(suggestPeerAddress(m.svc, t.ID), m.spin.Tick)
	case key.Matches(msg, m.keys.Delete):
		return m.startDelete()
	case key.Matches(msg, m.keys.View):
		return m.startFetchConfig(purposeView)
	case key.Matches(msg, m.keys.QR):
		return m.startFetchQR()
	case key.Matches(msg, m.keys.Copy):
		return m.startFetchConfig(purposeCopy)
	case key.Matches(msg, m.keys.Export):
		return m.startExport()
	case key.Matches(msg, m.keys.Import):
		return m.startImportPrompt()
	case key.Matches(msg, m.keys.Email):
		return m.startEmailPrompt()
	case key.Matches(msg, m.keys.Toggle):
		return m.startToggle()
	case key.Matches(msg, m.keys.Firewall):
		return m.startFirewallRules()
	case key.Matches(msg, m.keys.Routing):
		return m.startRoutingPrompt()
	}
	return m, nil
}

func (m model) moveCursor(delta int) (tea.Model, tea.Cmd) {
	if m.pane == paneTenants {
		n := len(m.tenants)
		if n == 0 {
			return m, nil
		}
		old := m.tenantCursor
		m.tenantCursor = (m.tenantCursor + delta + n) % n
		if m.tenantCursor != old {
			m.peerCursor = 0
			return m, loadPeers(m.svc, m.tenants[m.tenantCursor].ID)
		}
		return m, nil
	}
	n := len(m.peers)
	if n == 0 {
		return m, nil
	}
	m.peerCursor = (m.peerCursor + delta + n) % n
	return m, nil
}
