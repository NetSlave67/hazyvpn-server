package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"hazyvpn-server/internal/app"
)

// safeFileSegment strips anything that isn't a safe filename character, so
// tenant/peer names (which may contain spaces or punctuation) can't escape
// the export directory or collide with shell-special characters.
var unsafeFileChars = regexp.MustCompile(`[^a-zA-Z0-9_.-]+`)

func safeFileSegment(s string) string {
	s = unsafeFileChars.ReplaceAllString(s, "-")
	s = strings.Trim(s, "-")
	if s == "" {
		return "unnamed"
	}
	return s
}

// exportPeerToDir writes a peer's .conf and QR PNG into dir and returns the
// .conf path for display.
func exportPeerToDir(svc *app.Service, tenantID, peerID int64, dir string) (string, error) {
	tenants, err := svc.ListTenants(bgCtx)
	if err != nil {
		return "", err
	}
	tenantName := fmt.Sprintf("tenant-%d", tenantID)
	for _, t := range tenants {
		if t.ID == tenantID {
			tenantName = t.Name
			break
		}
	}
	peers, err := svc.ListPeers(bgCtx, tenantID)
	if err != nil {
		return "", err
	}
	peerName := fmt.Sprintf("peer-%d", peerID)
	for _, p := range peers {
		if p.ID == peerID {
			peerName = p.Name
			break
		}
	}

	text, err := svc.PeerConfigText(bgCtx, tenantID, peerID)
	if err != nil {
		return "", err
	}
	png, err := svc.PeerQRPNG(bgCtx, tenantID, peerID)
	if err != nil {
		return "", err
	}

	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating export directory: %w", err)
	}
	base := fmt.Sprintf("%s-%s", safeFileSegment(tenantName), safeFileSegment(peerName))
	confPath := filepath.Join(dir, base+".conf")
	qrPath := filepath.Join(dir, base+"-qr.png")

	if err := os.WriteFile(confPath, []byte(text), 0o600); err != nil {
		return "", fmt.Errorf("writing config: %w", err)
	}
	if err := os.WriteFile(qrPath, png, 0o600); err != nil {
		return "", fmt.Errorf("writing QR code: %w", err)
	}
	return confPath, nil
}

func exportTenantBackupToDir(svc *app.Service, tenantID int64, dir string) (string, error) {
	tenants, err := svc.ListTenants(bgCtx)
	if err != nil {
		return "", err
	}
	tenantName := fmt.Sprintf("tenant-%d", tenantID)
	for _, t := range tenants {
		if t.ID == tenantID {
			tenantName = t.Name
			break
		}
	}

	data, err := svc.ExportTenantBackup(bgCtx, tenantID)
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("creating export directory: %w", err)
	}
	stamp := time.Now().UTC().Format("20060102-150405")
	path := filepath.Join(dir, fmt.Sprintf("%s-backup-%s.json", safeFileSegment(tenantName), stamp))
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return "", fmt.Errorf("writing backup: %w", err)
	}
	return path, nil
}

// importPeerFromFile imports an external WireGuard peer config, naming the
// new peer after the file (minus its extension) so the operator doesn't
// have to type a name for something that already has one.
func importPeerFromFile(svc *app.Service, tenantID int64, path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	name := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	peer, err := svc.ImportPeerConfig(bgCtx, tenantID, name, string(data))
	if err != nil {
		return "", err
	}
	return peer.Name, nil
}

// importTenantFromFile restores a tenant backup, keeping its original name.
func importTenantFromFile(svc *app.Service, path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("reading %s: %w", path, err)
	}
	tenant, err := svc.ImportTenantBackup(bgCtx, data, "")
	if err != nil {
		return "", err
	}
	return tenant.Name, nil
}

func copyText(text string) error {
	return clipboard.WriteAll(text)
}
