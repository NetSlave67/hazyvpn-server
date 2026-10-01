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
	return m, fetchPeerStats(m.svc, msg.tenantID)
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

	case modalPromptExceptions:
		t := m.selectedTenant()
		if t == nil {
			m.modal, m.prompt = modalNone, nil
			return m, nil
		}
		exceptions := m.prompt.value("Exceptions")
		m.modal, m.prompt = modalNone, nil
		m.busy = true
		return m, tea.Batch(updateExceptions(m.svc, t.ID, exceptions), m.spin.Tick)
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

// startExceptionsPrompt opens the isolation-exceptions editor for the
// selected tenant (available from either pane — it's always a tenant-level
// setting), pre-filled with its current value.
func (m model) startExceptionsPrompt() (tea.Model, tea.Cmd) {
	t := m.selectedTenant()
	if t == nil {
		m.setMessage(warnStyle.Render("Select a tenant first"))
		return m, clearMessageAfter(messageTTL)
	}
	m.prompt = newPromptForm("Isolation Exceptions — "+t.Name, "Exceptions",
		"comma-separated IPs/CIDRs reachable despite isolation", t.IsolationExceptions)
	m.modal = modalPromptExceptions
	return m, nil
}
