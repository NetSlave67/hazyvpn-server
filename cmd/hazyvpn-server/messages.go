package main

import (
	"time"

	tea "charm.land/bubbletea/v2"
	"hazyvpn-server/internal/netns"
	"hazyvpn-server/internal/store"
)

// Every Service call that touches the database or shells out to the
// network stack runs in a tea.Cmd and reports back as one of these
// messages, so the UI thread never blocks on I/O.

type tenantsLoadedMsg struct {
	tenants []store.Tenant
	err     error
}

type peersLoadedMsg struct {
	tenantID int64
	peers    []store.Peer
	err      error
}

type tenantCreatedMsg struct {
	tenant *store.Tenant
	err    error
}

type tenantDeletedMsg struct {
	id  int64
	err error
}

type peerAddedMsg struct {
	peer *store.Peer
	err  error
}

type peerDeletedMsg struct {
	id  int64
	err error
}

// viewPurpose distinguishes what a rendered-text result is for, since
// PeerConfigText is reused by the view/export/copy/email flows.
type viewPurpose int

const (
	purposeView viewPurpose = iota
	purposeExport
	purposeCopy
)

type configTextMsg struct {
	text    string
	purpose viewPurpose
	err     error
}

type qrReadyMsg struct {
	text string
	err  error
}

type emailSentMsg struct {
	to  string
	err error
}

type exportedMsg struct {
	path string
	err  error
}

type importedPeerMsg struct {
	name string
	err  error
}

type importedTenantMsg struct {
	name string
	err  error
}

type clipboardCopiedMsg struct {
	err error
}

type tenantDefaultsMsg struct {
	subnet string
	port   int
	err    error
}

type peerDefaultsMsg struct {
	address string
	err     error
}

// peerStatsMsg carries live stats for one tenant's peers. A non-nil err
// (e.g. the tenant is disabled, so its namespace doesn't exist) is treated
// as "no stats available" rather than shown as an error — it's an entirely
// expected condition, not a failure.
type peerStatsMsg struct {
	tenantID int64
	stats    map[string]netns.PeerStat
	err      error
}

type toggleTenantEnabledMsg struct {
	tenantID int64
	err      error
}

type togglePeerEnabledMsg struct {
	peerID int64
	err    error
}

type exceptionsUpdatedMsg struct {
	err error
}

type clearMessageMsg struct{}

func clearMessageAfter(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return clearMessageMsg{} })
}
