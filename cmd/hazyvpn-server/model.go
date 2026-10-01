package main

import (
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"

	"hazyvpn-server/internal/app"
	"hazyvpn-server/internal/store"
)

type pane int

const (
	paneTenants pane = iota
	panePeers
)

type modalKind int

const (
	modalNone modalKind = iota
	modalHelp
	modalTenantForm
	modalPeerForm
	modalConfirmDeleteTenant
	modalConfirmDeletePeer
	modalViewText
	modalPromptEmail
	modalPromptImportPeer
	modalPromptImportTenant
)

type model struct {
	svc *app.Service

	width, height int
	pane          pane

	tenants      []store.Tenant
	tenantCursor int
	peers        []store.Peer
	peerCursor   int

	modal    modalKind
	form     *form
	prompt   *form // single-field form reused for email/import path prompts
	viewText string
	viewKind string // "Config" or "QR" — used as the view modal's heading

	keys keyMap
	help help.Model
	spin spinner.Model
	busy bool

	message    string
	messageExp time.Time

	publicHost string
	exportDir  string
}

func newModel(svc *app.Service, publicHost, exportDir string) model {
	sp := spinner.New(spinner.WithSpinner(spinner.Dot), spinner.WithStyle(spinnerStyle))
	return model{
		svc:        svc,
		keys:       newKeyMap(),
		help:       newHelp(),
		spin:       sp,
		publicHost: publicHost,
		exportDir:  exportDir,
	}
}

func (m model) Init() tea.Cmd {
	return loadTenants(m.svc)
}

func (m *model) setMessage(s string) {
	m.message = s
	m.messageExp = time.Now().Add(4 * time.Second)
}

func (m model) selectedTenant() *store.Tenant {
	if m.tenantCursor < 0 || m.tenantCursor >= len(m.tenants) {
		return nil
	}
	return &m.tenants[m.tenantCursor]
}

func (m model) selectedPeer() *store.Peer {
	if m.peerCursor < 0 || m.peerCursor >= len(m.peers) {
		return nil
	}
	return &m.peers[m.peerCursor]
}

func (m *model) clampCursors() {
	if m.tenantCursor >= len(m.tenants) {
		m.tenantCursor = max(0, len(m.tenants)-1)
	}
	if m.peerCursor >= len(m.peers) {
		m.peerCursor = max(0, len(m.peers)-1)
	}
}
