package main

import (
	"time"

	"charm.land/bubbles/v2/help"
	"charm.land/bubbles/v2/spinner"
	tea "charm.land/bubbletea/v2"

	"hazyvpn-server/internal/app"
	"hazyvpn-server/internal/netns"
	"hazyvpn-server/internal/store"
)

// statsRefreshInterval controls how often live peer stats (handshake time,
// transfer counters) are re-read from the kernel while the dashboard is
// visible — frequent enough to feel live, cheap enough not to matter.
const statsRefreshInterval = 3 * time.Second

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
	modalPromptExceptions
	modalPromptRouting
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

	// allStats holds live peer stats for every enabled tenant, keyed by
	// tenant ID and then by peer public key — fetched for every tenant (not
	// just the selected one) so the dashboard can show both a per-tenant
	// traffic total in each tenant row and an overall total in the header.
	// Refreshed whenever peers (re)load and on a periodic tick.
	//
	// prevStats/prevStatsAt hold the previous snapshot so tenantRate/
	// overallRate can compute a live bits-per-second rate (the cumulative
	// counters alone aren't what you want glanceable at the tenant/overall
	// level — a per-peer cumulative total, shown in the peers pane, is
	// still exactly what you want there).
	allStats    map[int64]map[string]netns.PeerStat
	statsAt     time.Time
	prevStats   map[int64]map[string]netns.PeerStat
	prevStatsAt time.Time

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
	return tea.Batch(loadTenants(m.svc), statsTick())
}

type statsTickMsg time.Time

func statsTick() tea.Cmd {
	return tea.Tick(statsRefreshInterval, func(t time.Time) tea.Msg { return statsTickMsg(t) })
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

// tenantRate returns the live download/upload rate, in bytes per second,
// for one tenant — the sum, across its peers, of each peer's byte-count
// delta between the current and previous stats snapshot, divided by the
// time between them. Zero when there's no previous snapshot yet (first
// tick after startup/selection) or no elapsed time, rather than a bogus
// spike or a divide-by-zero.
func (m model) tenantRate(tenantID int64) (rxBps, txBps float64) {
	elapsed := m.statsAt.Sub(m.prevStatsAt).Seconds()
	if elapsed <= 0 {
		return 0, 0
	}
	curr, prev := m.allStats[tenantID], m.prevStats[tenantID]
	var rxDelta, txDelta int64
	for key, c := range curr {
		p, ok := prev[key]
		if !ok {
			continue // peer is new since the last sample — nothing to diff against yet
		}
		if c.RxBytes > p.RxBytes {
			rxDelta += c.RxBytes - p.RxBytes
		}
		if c.TxBytes > p.TxBytes {
			txDelta += c.TxBytes - p.TxBytes
		}
	}
	return float64(rxDelta) / elapsed, float64(txDelta) / elapsed
}

// overallRate sums tenantRate across every tenant currently known.
func (m model) overallRate() (rxBps, txBps float64) {
	for tenantID := range m.allStats {
		r, t := m.tenantRate(tenantID)
		rxBps += r
		txBps += t
	}
	return rxBps, txBps
}
