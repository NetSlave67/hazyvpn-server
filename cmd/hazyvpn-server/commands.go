package main

import (
	"context"

	tea "charm.land/bubbletea/v2"
	"hazyvpn-server/internal/app"
)

// bgCtx is used for commands fired from the TUI's event loop. The program
// is short-lived and single-user; a background context is adequate since
// there's no request scope to cancel.
var bgCtx = context.Background()

func loadTenants(svc *app.Service) tea.Cmd {
	return func() tea.Msg {
		tenants, err := svc.ListTenants(bgCtx)
		return tenantsLoadedMsg{tenants: tenants, err: err}
	}
}

func loadPeers(svc *app.Service, tenantID int64) tea.Cmd {
	return func() tea.Msg {
		peers, err := svc.ListPeers(bgCtx, tenantID)
		return peersLoadedMsg{tenantID: tenantID, peers: peers, err: err}
	}
}

func createTenant(svc *app.Service, p app.CreateTenantParams) tea.Cmd {
	return func() tea.Msg {
		tenant, err := svc.CreateTenant(bgCtx, p)
		return tenantCreatedMsg{tenant: tenant, err: err}
	}
}

func deleteTenant(svc *app.Service, id int64) tea.Cmd {
	return func() tea.Msg {
		err := svc.DeleteTenant(bgCtx, id)
		return tenantDeletedMsg{id: id, err: err}
	}
}

func addPeer(svc *app.Service, p app.AddPeerParams) tea.Cmd {
	return func() tea.Msg {
		peer, err := svc.AddPeer(bgCtx, p)
		return peerAddedMsg{peer: peer, err: err}
	}
}

func removePeer(svc *app.Service, tenantID, peerID int64) tea.Cmd {
	return func() tea.Msg {
		err := svc.RemovePeer(bgCtx, tenantID, peerID)
		return peerDeletedMsg{id: peerID, err: err}
	}
}

func fetchPeerConfigText(svc *app.Service, tenantID, peerID int64, purpose viewPurpose) tea.Cmd {
	return func() tea.Msg {
		text, err := svc.PeerConfigText(bgCtx, tenantID, peerID)
		return configTextMsg{text: text, purpose: purpose, err: err}
	}
}

func fetchPeerQR(svc *app.Service, tenantID, peerID int64) tea.Cmd {
	return func() tea.Msg {
		text, err := svc.PeerQRTerminal(bgCtx, tenantID, peerID)
		return qrReadyMsg{text: text, err: err}
	}
}

func emailPeer(svc *app.Service, tenantID, peerID int64, to string) tea.Cmd {
	return func() tea.Msg {
		err := svc.EmailPeerConfig(bgCtx, tenantID, peerID, to)
		return emailSentMsg{to: to, err: err}
	}
}

func exportPeer(svc *app.Service, tenantID, peerID int64, dir string) tea.Cmd {
	return func() tea.Msg {
		path, err := exportPeerToDir(svc, tenantID, peerID, dir)
		return exportedMsg{path: path, err: err}
	}
}

func exportTenantBackup(svc *app.Service, tenantID int64, dir string) tea.Cmd {
	return func() tea.Msg {
		path, err := exportTenantBackupToDir(svc, tenantID, dir)
		return exportedMsg{path: path, err: err}
	}
}

func importPeer(svc *app.Service, tenantID int64, path string) tea.Cmd {
	return func() tea.Msg {
		name, err := importPeerFromFile(svc, tenantID, path)
		return importedPeerMsg{name: name, err: err}
	}
}

func importTenant(svc *app.Service, path, newName string, newListenPort int) tea.Cmd {
	return func() tea.Msg {
		name, err := importTenantFromFile(svc, path, newName, newListenPort)
		return importedTenantMsg{name: name, err: err}
	}
}

func suggestTenantDefaults(svc *app.Service) tea.Cmd {
	return func() tea.Msg {
		subnet, err := svc.SuggestSubnet(bgCtx)
		if err != nil {
			return tenantDefaultsMsg{err: err}
		}
		port, err := svc.SuggestListenPort(bgCtx)
		if err != nil {
			return tenantDefaultsMsg{err: err}
		}
		return tenantDefaultsMsg{subnet: subnet, port: port}
	}
}

func suggestPeerAddress(svc *app.Service, tenantID int64) tea.Cmd {
	return func() tea.Msg {
		addr, err := svc.SuggestNextPeerAddress(bgCtx, tenantID)
		if err != nil {
			return peerDefaultsMsg{err: err}
		}
		return peerDefaultsMsg{address: addr.String()}
	}
}

func copyToClipboard(text string) tea.Cmd {
	return func() tea.Msg {
		return clipboardCopiedMsg{err: copyText(text)}
	}
}
