package main

import (
	"strconv"

	tea "charm.land/bubbletea/v2"
)

// --- Data-loaded message handlers ---------------------------------------

func (m model) onTenantsLoaded(msg tenantsLoadedMsg) (tea.Model, tea.Cmd) {
	if msg.err != nil {
		m.setMessage(errorStyle.Render("Loading tenants: " + msg.err.Error()))
		return m, clearMessageAfter(messageTTL)
	}
	m.tenants = msg.tenants
	m.clampCursors()
	if t := m.selectedTenant(); t != nil {
		return m, loadPeers(m.svc, t.ID)
	}
	m.peers = nil
	return m, nil
}

func (m model) onPeersLoaded(msg peersLoadedMsg) (tea.Model, tea.Cmd) {
	t := m.selectedTenant()
	if t == nil || t.ID != msg.tenantID {
		return m, nil // selection moved on before this response arrived
	}
	if msg.err != nil {
		m.setMessage(errorStyle.Render("Loading peers: " + msg.err.Error()))
		return m, clearMessageAfter(messageTTL)
	}
	m.peers = msg.peers
	m.clampCursors()
	return m, fetchAllStats(m.svc)
}

func (m model) onTenantDefaults(msg tenantDefaultsMsg) (tea.Model, tea.Cmd) {
	m.busy = false
	if msg.err != nil {
		m.setMessage(errorStyle.Render("Could not suggest defaults: " + msg.err.Error()))
		return m, clearMessageAfter(messageTTL)
	}
	m.form = newTenantFormModel(msg.subnet, msg.port)
	m.modal = modalTenantForm
	return m, nil
}

func (m model) onPeerDefaults(msg peerDefaultsMsg) (tea.Model, tea.Cmd) {
	m.busy = false
	t := m.selectedTenant()
	if t == nil {
		return m, nil
	}
	if msg.err != nil {
		m.setMessage(errorStyle.Render("Could not suggest an address: " + msg.err.Error()))
		return m, clearMessageAfter(messageTTL)
	}
	m.form = newPeerFormModel(t, msg.address)
	m.modal = modalPeerForm
	return m, nil
}

func (m model) onTenantCreated(msg tenantCreatedMsg) (tea.Model, tea.Cmd) {
	m.busy = false
	if msg.err != nil {
		if m.form != nil {
			m.form.errMsg = msg.err.Error()
		}
		return m, nil
	}
	m.modal, m.form = modalNone, nil
	m.setMessage(activeStyle.Render("Created tenant " + msg.tenant.Name))
	return m, tea.Batch(loadTenants(m.svc), clearMessageAfter(messageTTL))
}

func (m model) onTenantDeleted(msg tenantDeletedMsg) (tea.Model, tea.Cmd) {
	m.busy = false
	if msg.err != nil {
		m.setMessage(errorStyle.Render("Delete failed: " + msg.err.Error()))
		return m, clearMessageAfter(messageTTL)
	}
	m.setMessage(dimStyle.Render("Tenant deleted"))
	m.peers = nil
	return m, tea.Batch(loadTenants(m.svc), clearMessageAfter(messageTTL))
}

func (m model) onPeerAdded(msg peerAddedMsg) (tea.Model, tea.Cmd) {
	m.busy = false
	if msg.err != nil {
		if m.form != nil {
			m.form.errMsg = msg.err.Error()
		}
		return m, nil
	}
	m.modal, m.form = modalNone, nil
	m.setMessage(activeStyle.Render("Added peer " + msg.peer.Name))
	if t := m.selectedTenant(); t != nil {
		return m, tea.Batch(loadPeers(m.svc, t.ID), clearMessageAfter(messageTTL))
	}
	return m, clearMessageAfter(messageTTL)
}

func (m model) onPeerDeleted(msg peerDeletedMsg) (tea.Model, tea.Cmd) {
	m.busy = false
	if msg.err != nil {
		m.setMessage(errorStyle.Render("Delete failed: " + msg.err.Error()))
		return m, clearMessageAfter(messageTTL)
	}
	m.setMessage(dimStyle.Render("Peer deleted"))
	if t := m.selectedTenant(); t != nil {
		return m, tea.Batch(loadPeers(m.svc, t.ID), clearMessageAfter(messageTTL))
	}
	return m, clearMessageAfter(messageTTL)
}

func (m model) onConfigText(msg configTextMsg) (tea.Model, tea.Cmd) {
	m.busy = false
	if msg.err != nil {
		m.setMessage(errorStyle.Render("Could not render config: " + msg.err.Error()))
		return m, clearMessageAfter(messageTTL)
	}
	switch msg.purpose {
	case purposeCopy:
		m.busy = true
		return m, tea.Batch(copyToClipboard(msg.text), m.spin.Tick)
	default:
		m.viewText, m.viewKind, m.modal = msg.text, "Config", modalViewText
		return m, nil
	}
}

func (m model) onQRReady(msg qrReadyMsg) (tea.Model, tea.Cmd) {
	m.busy = false
	if msg.err != nil {
		m.setMessage(errorStyle.Render("Could not render QR code: " + msg.err.Error()))
		return m, clearMessageAfter(messageTTL)
	}
	m.viewText, m.viewKind, m.modal = msg.text, "QR Code", modalViewText
	return m, nil
}

// --- Modal key handlers --------------------------------------------------

func (m model) updateTenantForm(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "esc" {
		m.modal, m.form = modalNone, nil
		return m, nil
	}
	submitted, cmd := m.form.handleKey(msg)
	if !submitted {
		return m, cmd
	}
	params, err := tenantParamsFromForm(m.form)
	if err != nil {
		m.form.errMsg = err.Error()
		return m, nil
	}
	m.form.errMsg = ""
	m.busy = true
	return m, tea.Batch(createTenant(m.svc, params), m.spin.Tick)
}

func (m model) updatePeerForm(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "esc" {
		m.modal, m.form = modalNone, nil
		return m, nil
	}
	submitted, cmd := m.form.handleKey(msg)
	if !submitted {
		return m, cmd
	}
	t := m.selectedTenant()
	if t == nil {
		m.modal, m.form = modalNone, nil
		return m, nil
	}
	params, err := peerParamsFromForm(m.form, t.ID)
	if err != nil {
		m.form.errMsg = err.Error()
		return m, nil
	}
	m.form.errMsg = ""
	m.busy = true
	return m, tea.Batch(addPeer(m.svc, params), m.spin.Tick)
}

func (m model) updateConfirmDeleteTenant(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	m.modal = modalNone
	if msg.String() != "y" && msg.String() != "enter" {
		return m, nil
	}
	t := m.selectedTenant()
	if t == nil {
		return m, nil
	}
	m.busy = true
	return m, tea.Batch(deleteTenant(m.svc, t.ID), m.spin.Tick)
}

func (m model) updateConfirmDeletePeer(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	m.modal = modalNone
	if msg.String() != "y" && msg.String() != "enter" {
		return m, nil
	}
	t := m.selectedTenant()
	p := m.selectedPeer()
	if t == nil || p == nil {
		return m, nil
	}
	m.busy = true
	return m, tea.Batch(removePeer(m.svc, t.ID, p.ID), m.spin.Tick)
}

func (m model) updatePrompt(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "esc" {
		m.modal, m.prompt = modalNone, nil
		return m, nil
	}
	submitted, cmd := m.prompt.handleKey(msg)
	if !submitted {
		return m, cmd
	}

	switch m.modal {
	case modalPromptEmail:
		to := m.prompt.value("To")
		if to == "" {
			m.prompt.errMsg = "an email address is required"
			return m, nil
		}
		t, p := m.selectedTenant(), m.selectedPeer()
		if t == nil || p == nil {
			m.modal, m.prompt = modalNone, nil
			return m, nil
		}
		m.modal, m.prompt = modalNone, nil
		m.busy = true
		return m, tea.Batch(emailPeer(m.svc, t.ID, p.ID, to), m.spin.Tick)

	case modalPromptImportPeer:
		path := m.prompt.value("Path")
		if path == "" {
			m.prompt.errMsg = "a file path is required"
			return m, nil
		}
		t := m.selectedTenant()
		if t == nil {
			m.modal, m.prompt = modalNone, nil
			return m, nil
		}
		m.modal, m.prompt = modalNone, nil
		m.busy = true
		return m, tea.Batch(importPeer(m.svc, t.ID, path), m.spin.Tick)

	case modalPromptImportTenant:
		path := m.prompt.value("Path")
		if path == "" {
			m.prompt.errMsg = "a file path is required"
			return m, nil
		}
		newName := m.prompt.value("New Name")
		newPort := 0
		if v := m.prompt.value("New Listen Port"); v != "" {
			p, err := strconv.Atoi(v)
			if err != nil {
				m.prompt.errMsg = "listen port must be a number"
				return m, nil
			}
			newPort = p
		}
		m.modal, m.prompt = modalNone, nil
		m.busy = true
		return m, tea.Batch(importTenant(m.svc, path, newName, newPort), m.spin.Tick)

	case modalPromptRouting:
		t, p := m.selectedTenant(), m.selectedPeer()
		if t == nil || p == nil {
			m.modal, m.prompt = modalNone, nil
			return m, nil
		}
		allowedIPs := m.prompt.value("Allowed IPs")
		if allowedIPs == "" {
			m.prompt.errMsg = "allowed IPs is required"
			return m, nil
		}
		routedPrefixes := m.prompt.value("Routed Prefixes")
		m.modal, m.prompt = modalNone, nil
		m.busy = true
		return m, tea.Batch(updatePeerRouting(m.svc, t.ID, p.ID, allowedIPs, routedPrefixes), m.spin.Tick)
	}
	return m, nil
}

// --- Action starters (normal-mode key handlers) ---------------------------

func (m model) startDelete() (tea.Model, tea.Cmd) {
	if m.pane == paneTenants {
		if m.selectedTenant() == nil {
			m.setMessage(warnStyle.Render("Select a tenant first"))
			return m, clearMessageAfter(messageTTL)
		}
		m.modal = modalConfirmDeleteTenant
		return m, nil
	}
	if m.selectedPeer() == nil {
		m.setMessage(warnStyle.Render("Select a peer first"))
		return m, clearMessageAfter(messageTTL)
	}
	m.modal = modalConfirmDeletePeer
	return m, nil
}

func (m model) startFetchConfig(purpose viewPurpose) (tea.Model, tea.Cmd) {
	t, p := m.selectedTenant(), m.selectedPeer()
	if m.pane != panePeers || t == nil || p == nil {
		m.setMessage(warnStyle.Render("Select a peer first"))
		return m, clearMessageAfter(messageTTL)
	}
	m.busy = true
	return m, tea.Batch(fetchPeerConfigText(m.svc, t.ID, p.ID, purpose), m.spin.Tick)
}

func (m model) startFetchQR() (tea.Model, tea.Cmd) {
	t, p := m.selectedTenant(), m.selectedPeer()
	if m.pane != panePeers || t == nil || p == nil {
		m.setMessage(warnStyle.Render("Select a peer first"))
		return m, clearMessageAfter(messageTTL)
	}
	m.busy = true
	return m, tea.Batch(fetchPeerQR(m.svc, t.ID, p.ID), m.spin.Tick)
}

func (m model) startExport() (tea.Model, tea.Cmd) {
	if m.pane == paneTenants {
		t := m.selectedTenant()
		if t == nil {
			m.setMessage(warnStyle.Render("Select a tenant first"))
			return m, clearMessageAfter(messageTTL)
		}
		m.busy = true
		return m, tea.Batch(exportTenantBackup(m.svc, t.ID, m.exportDir), m.spin.Tick)
	}
	t, p := m.selectedTenant(), m.selectedPeer()
	if t == nil || p == nil {
		m.setMessage(warnStyle.Render("Select a peer first"))
		return m, clearMessageAfter(messageTTL)
	}
	m.busy = true
	return m, tea.Batch(exportPeer(m.svc, t.ID, p.ID, m.exportDir), m.spin.Tick)
}

func (m model) startImportPrompt() (tea.Model, tea.Cmd) {
	if m.pane == paneTenants {
		f := newForm("Import Tenant Backup")
		f.addText("Path", "path to a backup .json file", "")
		f.addText("New Name", "optional — overrides the name stored in the backup", "")
		f.addText("New Listen Port", "optional — required if the original port is still in use", "")
		f.focusField()
		m.prompt = f
		m.modal = modalPromptImportTenant
		return m, nil
	}
	if t := m.selectedTenant(); t == nil {
		m.setMessage(warnStyle.Render("Select a tenant first"))
		return m, clearMessageAfter(messageTTL)
	}
	m.prompt = newPromptForm("Import Peer Config", "Path", "path to a .conf file", "")
	m.modal = modalPromptImportPeer
	return m, nil
}

func (m model) startEmailPrompt() (tea.Model, tea.Cmd) {
	t, p := m.selectedTenant(), m.selectedPeer()
	if m.pane != panePeers || t == nil || p == nil {
		m.setMessage(warnStyle.Render("Select a peer first"))
		return m, clearMessageAfter(messageTTL)
	}
	m.prompt = newPromptForm("Email Config", "To", "recipient email address", "")
	m.modal = modalPromptEmail
	return m, nil
}

// startToggle flips the enabled/disabled state of whatever's selected in
// the active pane: a tenant (tears its namespace down/back up) or a peer
// (excludes/re-includes it from the tenant's live WireGuard config).
func (m model) startToggle() (tea.Model, tea.Cmd) {
	if m.pane == paneTenants {
		t := m.selectedTenant()
		if t == nil {
			m.setMessage(warnStyle.Render("Select a tenant first"))
			return m, clearMessageAfter(messageTTL)
		}
		m.busy = true
		return m, tea.Batch(toggleTenantEnabled(m.svc, t.ID, !t.Enabled), m.spin.Tick)
	}
	t, p := m.selectedTenant(), m.selectedPeer()
	if t == nil || p == nil {
		m.setMessage(warnStyle.Render("Select a peer first"))
		return m, clearMessageAfter(messageTTL)
	}
	m.busy = true
	return m, tea.Batch(togglePeerEnabled(m.svc, t.ID, p.ID, !p.Enabled), m.spin.Tick)
}

// startFirewallRules opens the firewall-rules list for the selected tenant
// (available from either pane — it's always a tenant-level setting).
func (m model) startFirewallRules() (tea.Model, tea.Cmd) {
	t := m.selectedTenant()
	if t == nil {
		m.setMessage(warnStyle.Render("Select a tenant first"))
		return m, clearMessageAfter(messageTTL)
	}
	m.modal = modalFirewallRules
	m.firewallCursor = 0
	m.busy = true
	return m, tea.Batch(loadFirewallRules(m.svc, t.ID), m.spin.Tick)
}

// --- Firewall rules modal --------------------------------------------------

func (m model) onFirewallRulesLoaded(msg firewallRulesLoadedMsg) (tea.Model, tea.Cmd) {
	m.busy = false
	t := m.selectedTenant()
	if t == nil || t.ID != msg.tenantID {
		return m, nil // selection moved on before this response arrived
	}
	if msg.err != nil {
		m.setMessage(errorStyle.Render("Loading firewall rules: " + msg.err.Error()))
		m.modal = modalNone
		return m, clearMessageAfter(messageTTL)
	}
	m.firewallRules = msg.rules
	if m.firewallTrackID != 0 {
		for i, r := range m.firewallRules {
			if r.ID == m.firewallTrackID {
				m.firewallCursor = i
				break
			}
		}
		m.firewallTrackID = 0
	}
	if m.firewallCursor >= len(m.firewallRules) {
		m.firewallCursor = max(0, len(m.firewallRules)-1)
	}
	return m, nil
}

func (m model) onFirewallRuleAdded(msg firewallRuleAddedMsg) (tea.Model, tea.Cmd) {
	m.busy = false
	if msg.err != nil {
		if m.form != nil {
			m.form.errMsg = msg.err.Error()
		}
		return m, nil
	}
	m.modal, m.form = modalFirewallRules, nil
	m.setMessage(activeStyle.Render("Firewall rule added"))
	if msg.rule != nil {
		m.firewallTrackID = msg.rule.ID
	}
	t := m.selectedTenant()
	if t == nil {
		return m, clearMessageAfter(messageTTL)
	}
	return m, tea.Batch(loadFirewallRules(m.svc, t.ID), clearMessageAfter(messageTTL))
}

func (m model) onFirewallRuleDeleted(msg firewallRuleDeletedMsg) (tea.Model, tea.Cmd) {
	m.busy = false
	if msg.err != nil {
		m.setMessage(errorStyle.Render("Delete failed: " + msg.err.Error()))
		return m, clearMessageAfter(messageTTL)
	}
	m.setMessage(dimStyle.Render("Firewall rule deleted"))
	t := m.selectedTenant()
	if t == nil {
		return m, clearMessageAfter(messageTTL)
	}
	return m, tea.Batch(loadFirewallRules(m.svc, t.ID), clearMessageAfter(messageTTL))
}

func (m model) onFirewallRuleMoved(msg firewallRuleMovedMsg) (tea.Model, tea.Cmd) {
	m.busy = false
	if msg.err != nil {
		m.setMessage(errorStyle.Render("Reorder failed: " + msg.err.Error()))
		return m, clearMessageAfter(messageTTL)
	}
	t := m.selectedTenant()
	if t == nil {
		return m, nil
	}
	return m, loadFirewallRules(m.svc, t.ID)
}

// updateFirewallRules handles keys while the firewall-rules list modal is
// open: navigate with the normal up/down keys, shift+k/shift+j to reorder
// (regular j/k are already taken by navigation, same as everywhere else in
// this app), a to add, x to delete (with confirmation), esc to close.
func (m model) updateFirewallRules(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	t := m.selectedTenant()
	if t == nil {
		m.modal = modalNone
		return m, nil
	}
	switch msg.String() {
	case "esc", "q":
		m.modal = modalNone
		return m, nil
	case "up", "k":
		if n := len(m.firewallRules); n > 0 {
			m.firewallCursor = (m.firewallCursor - 1 + n) % n
		}
		return m, nil
	case "down", "j":
		if n := len(m.firewallRules); n > 0 {
			m.firewallCursor = (m.firewallCursor + 1) % n
		}
		return m, nil
	case "K":
		r := m.selectedFirewallRule()
		if r == nil {
			return m, nil
		}
		m.firewallTrackID = r.ID
		m.busy = true
		return m, tea.Batch(moveFirewallRule(m.svc, t.ID, r.ID, true), m.spin.Tick)
	case "J":
		r := m.selectedFirewallRule()
		if r == nil {
			return m, nil
		}
		m.firewallTrackID = r.ID
		m.busy = true
		return m, tea.Batch(moveFirewallRule(m.svc, t.ID, r.ID, false), m.spin.Tick)
	case "a":
		m.form = newFirewallRuleFormModel(t.Name)
		m.modal = modalFirewallRuleForm
		return m, nil
	case "x":
		if m.selectedFirewallRule() == nil {
			return m, nil
		}
		m.modal = modalConfirmDeleteFirewallRule
		return m, nil
	}
	return m, nil
}

func (m model) updateFirewallRuleForm(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	if msg.String() == "esc" {
		m.modal, m.form = modalFirewallRules, nil
		return m, nil
	}
	submitted, cmd := m.form.handleKey(msg)
	if !submitted {
		return m, cmd
	}
	t := m.selectedTenant()
	if t == nil {
		m.modal, m.form = modalNone, nil
		return m, nil
	}
	in, err := firewallRuleInputFromForm(m.form, t.ID)
	if err != nil {
		m.form.errMsg = err.Error()
		return m, nil
	}
	m.form.errMsg = ""
	m.busy = true
	return m, tea.Batch(addFirewallRule(m.svc, in), m.spin.Tick)
}

func (m model) updateConfirmDeleteFirewallRule(msg tea.KeyPressMsg) (tea.Model, tea.Cmd) {
	t := m.selectedTenant()
	r := m.selectedFirewallRule()
	if msg.String() != "y" && msg.String() != "enter" {
		m.modal = modalFirewallRules
		return m, nil
	}
	m.modal = modalFirewallRules
	if t == nil || r == nil {
		return m, nil
	}
	m.busy = true
	return m, tea.Batch(deleteFirewallRule(m.svc, t.ID, r.ID), m.spin.Tick)
}

// startRoutingPrompt opens the routing editor for the selected peer: its
// client-facing AllowedIPs and its server-side RoutedPrefixes, both
// editable without touching its keys or address.
func (m model) startRoutingPrompt() (tea.Model, tea.Cmd) {
	t, p := m.selectedTenant(), m.selectedPeer()
	if m.pane != panePeers || t == nil || p == nil {
		m.setMessage(warnStyle.Render("Select a peer first"))
		return m, clearMessageAfter(messageTTL)
	}
	f := newForm("Edit Routing — " + p.Name)
	f.addText("Allowed IPs", "handed to the client — what it tunnels", p.AllowedIPs)
	f.addText("Routed Prefixes", "optional — extra subnets the server routes to this peer", p.RoutedPrefixes)
	f.focusField()
	m.prompt = f
	m.modal = modalPromptRouting
	return m, nil
}
