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

// allStatsMsg carries live stats for every enabled tenant's peers (see
// app.Service.AllPeerStats). A non-nil err means the tenant list itself
// couldn't be read — a per-tenant namespace hiccup is already absorbed
// inside AllPeerStats, not surfaced here.
type allStatsMsg struct {
	stats map[int64]map[string]netns.PeerStat
	err   error
}

type toggleTenantEnabledMsg struct {
	tenantID int64
	err      error
}

type togglePeerEnabledMsg struct {
	peerID int64
	err    error
}

type peerRoutingUpdatedMsg struct {
	err error
}

type firewallRulesLoadedMsg struct {
	tenantID int64
	rules    []store.FirewallRule
	err      error
}

type firewallRuleAddedMsg struct {
	rule *store.FirewallRule
	err  error
}

type firewallRuleDeletedMsg struct {
	id  int64
	err error
}

type firewallRuleMovedMsg struct {
	err error
}

type clearMessageMsg struct{}

func clearMessageAfter(d time.Duration) tea.Cmd {
	return tea.Tick(d, func(time.Time) tea.Msg { return clearMessageMsg{} })
}
