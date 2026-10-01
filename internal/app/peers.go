package app

import (
	"context"
	"fmt"
	"net"

	"hazyvpn-server/internal/ipam"
	"hazyvpn-server/internal/mail"
	"hazyvpn-server/internal/qrcode"
	"hazyvpn-server/internal/store"
	"hazyvpn-server/internal/wgconf"
)

// --- Peers ---------------------------------------------------------------

// AddPeerParams are the operator-facing fields for a new road-warrior peer.
// Address, AllowedIPs, DNS, and Keepalive fall back to the tenant's
// defaults (and an auto-scanned free IP) when left empty/zero.
type AddPeerParams struct {
	TenantID      int64
	Name          string
	Address       string // empty => auto-assigned via SuggestNextPeerAddress
	AllowedIPs    string // empty => tenant default
	DNS           string // empty => tenant default
	Keepalive     int    // 0 => tenant default
	WithPreshared *bool  // nil => tenant default (PSKRequired)
}

// SuggestNextPeerAddress scans a tenant's existing peers and returns the
// first free host address in its subnet, so the operator never has to type
// an IP by hand.
func (s *Service) SuggestNextPeerAddress(ctx context.Context, tenantID int64) (net.IP, error) {
	tenant, err := s.store.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	subnet, err := ipam.ParseSubnet(tenant.Subnet)
	if err != nil {
		return nil, err
	}
	used, err := s.usedAddresses(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return ipam.Next(subnet, used)
}

func (s *Service) usedAddresses(ctx context.Context, tenantID int64) ([]net.IP, error) {
	peers, err := s.store.ListPeers(ctx, tenantID)
	if err != nil {
		return nil, fmt.Errorf("app: listing peers: %w", err)
	}
	used := make([]net.IP, 0, len(peers))
	for _, p := range peers {
		used = append(used, net.ParseIP(p.Address))
	}
	return used, nil
}

// AddPeer validates (or auto-assigns) the peer's address against the
// tenant's subnet and existing peers, generates its keypair, persists it,
// and pushes the updated config to the tenant's live WireGuard interface.
func (s *Service) AddPeer(ctx context.Context, p AddPeerParams) (*store.Peer, error) {
	tenant, err := s.store.GetTenant(ctx, p.TenantID)
	if err != nil {
		return nil, err
	}
	subnet, err := ipam.ParseSubnet(tenant.Subnet)
	if err != nil {
		return nil, err
	}
	used, err := s.usedAddresses(ctx, p.TenantID)
	if err != nil {
		return nil, err
	}

	addr := net.ParseIP(p.Address)
	if p.Address == "" {
		addr, err = ipam.Next(subnet, used)
		if err != nil {
			return nil, err
		}
	} else if addr == nil {
		return nil, fmt.Errorf("app: %q is not a valid IP address", p.Address)
	}
	if err := ipam.Validate(subnet, addr, used); err != nil {
		return nil, err
	}

	keypair, err := wgconf.GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("app: generating peer keypair: %w", err)
	}

	withPSK := tenant.PSKRequired
	if p.WithPreshared != nil {
		withPSK = *p.WithPreshared
	}
	var psk string
	if withPSK {
		key, err := wgconf.GeneratePresharedKey()
		if err != nil {
			return nil, fmt.Errorf("app: generating preshared key: %w", err)
		}
		psk = key.String()
	}

	allowedIPs := p.AllowedIPs
	if allowedIPs == "" {
		allowedIPs = tenant.AllowedIPs
	}
	dns := p.DNS
	if dns == "" {
		dns = tenant.DNS
	}
	keepalive := p.Keepalive
	if keepalive <= 0 {
		keepalive = tenant.Keepalive
	}

	peer, err := s.store.CreatePeer(ctx, store.PeerInput{
		TenantID:     p.TenantID,
		Name:         p.Name,
		Address:      addr.String(),
		PublicKey:    keypair.Public.String(),
		PrivateKey:   keypair.Private.String(),
		PresharedKey: psk,
		AllowedIPs:   allowedIPs,
		DNS:          dns,
		Keepalive:    keepalive,
	})
	if err != nil {
		return nil, err
	}

	if err := s.syncTenantWireGuard(ctx, tenant); err != nil {
		_ = s.store.DeletePeer(ctx, peer.ID) // don't leave a peer that was never actually applied
		return nil, err
	}
	return peer, nil
}

// RemovePeer deletes a peer and pushes the updated (peer-less-one) config
// to the tenant's live WireGuard interface.
func (s *Service) RemovePeer(ctx context.Context, tenantID, peerID int64) error {
	tenant, err := s.store.GetTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	if err := s.store.DeletePeer(ctx, peerID); err != nil {
		return err
	}
	return s.syncTenantWireGuard(ctx, tenant)
}

func (s *Service) ListPeers(ctx context.Context, tenantID int64) ([]store.Peer, error) {
	return s.store.ListPeers(ctx, tenantID)
}

// PeerConfigText renders the full client-side .conf for a peer, ready to
// download, copy, or email.
func (s *Service) PeerConfigText(ctx context.Context, tenantID, peerID int64) (string, error) {
	tenant, err := s.store.GetTenant(ctx, tenantID)
	if err != nil {
		return "", err
	}
	peer, err := s.store.GetPeer(ctx, peerID)
	if err != nil {
		return "", err
	}
	if peer.TenantID != tenantID {
		return "", fmt.Errorf("app: peer %d does not belong to tenant %d", peerID, tenantID)
	}

	ones, _ := mustSubnetPrefix(tenant.Subnet)
	return wgconf.RenderPeerConfig(wgconf.PeerConfig{
		Name:                peer.Name,
		PrivateKey:          peer.PrivateKey,
		Address:             fmt.Sprintf("%s/%d", peer.Address, ones),
		DNS:                 peer.DNS,
		ServerPublicKey:     tenant.ServerPublicKey,
		PresharedKey:        peer.PresharedKey,
		Endpoint:            fmt.Sprintf("%s:%d", s.publicHost, tenant.ListenPort),
		AllowedIPs:          peer.AllowedIPs,
		PersistentKeepalive: peer.Keepalive,
	}), nil
}

func mustSubnetPrefix(cidr string) (int, error) {
	subnet, err := ipam.ParseSubnet(cidr)
	if err != nil {
		return 0, err
	}
	ones, _ := subnet.Mask.Size()
	return ones, nil
}

// PeerQRPNG renders a peer's config as a QR code PNG, for export or email.
func (s *Service) PeerQRPNG(ctx context.Context, tenantID, peerID int64) ([]byte, error) {
	text, err := s.PeerConfigText(ctx, tenantID, peerID)
	if err != nil {
		return nil, err
	}
	return qrcode.PNG(text, 256)
}

// PeerQRTerminal renders a peer's config as a QR code for direct display in
// the TUI.
func (s *Service) PeerQRTerminal(ctx context.Context, tenantID, peerID int64) (string, error) {
	text, err := s.PeerConfigText(ctx, tenantID, peerID)
	if err != nil {
		return "", err
	}
	return qrcode.Terminal(text)
}

// EmailPeerConfig sends a peer's config (and QR code) to the given address.
func (s *Service) EmailPeerConfig(ctx context.Context, tenantID, peerID int64, to string) error {
	tenant, err := s.store.GetTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	peer, err := s.store.GetPeer(ctx, peerID)
	if err != nil {
		return err
	}
	configText, err := s.PeerConfigText(ctx, tenantID, peerID)
	if err != nil {
		return err
	}
	qrPNG, err := qrcode.PNG(configText, 256)
	if err != nil {
		return fmt.Errorf("app: rendering QR code: %w", err)
	}
	return mail.Send(s.smtp, mail.PeerConfigMail{
		To:          to,
		TenantName:  tenant.Name,
		PeerName:    peer.Name,
		ConfigText:  configText,
		ConfigQRPNG: qrPNG,
	})
}

// ImportPeerConfig validates an externally-produced WireGuard peer config
// (refusing PreUp/PostUp/PreDown/PostDown hooks, same rule the client-side
// TUI enforces) and adds it to a tenant, preserving its original keys and
// address rather than generating new ones.
func (s *Service) ImportPeerConfig(ctx context.Context, tenantID int64, name, configText string) (*store.Peer, error) {
	parsed, err := wgconf.Parse(configText)
	if err != nil {
		return nil, fmt.Errorf("app: parsing imported config: %w", err)
	}
	if hooks := parsed.DangerousHooks(); len(hooks) > 0 {
		return nil, fmt.Errorf("app: imported config runs %v on interface up/down, refusing to import", hooks)
	}

	privKeyStr := parsed.Interface["PrivateKey"]
	if privKeyStr == "" {
		return nil, fmt.Errorf("app: imported config has no PrivateKey")
	}
	privKey, err := wgconf.ParseKey(privKeyStr)
	if err != nil {
		return nil, fmt.Errorf("app: imported config has an invalid PrivateKey: %w", err)
	}
	addrCIDR := parsed.Interface["Address"]
	if addrCIDR == "" {
		return nil, fmt.Errorf("app: imported config has no Address")
	}
	addr, _, err := net.ParseCIDR(addrCIDR)
	if err != nil {
		// Some exported configs use a bare IP rather than a CIDR.
		addr = net.ParseIP(addrCIDR)
	}
	if addr == nil {
		return nil, fmt.Errorf("app: imported config has an invalid Address %q", addrCIDR)
	}

	tenant, err := s.store.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	subnet, err := ipam.ParseSubnet(tenant.Subnet)
	if err != nil {
		return nil, err
	}
	used, err := s.usedAddresses(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	if err := ipam.Validate(subnet, addr, used); err != nil {
		return nil, err
	}

	allowedIPs := defaultAllowedIPs
	dns := tenant.DNS
	keepalive := tenant.Keepalive
	if len(parsed.Peers) > 0 {
		if v := parsed.Peers[0]["AllowedIPs"]; v != "" {
			allowedIPs = v
		}
	}
	if v := parsed.Interface["DNS"]; v != "" {
		dns = v
	}

	peer, err := s.store.CreatePeer(ctx, store.PeerInput{
		TenantID:   tenantID,
		Name:       name,
		Address:    addr.String(),
		PublicKey:  privKey.PublicKey().String(),
		PrivateKey: privKey.String(),
		AllowedIPs: allowedIPs,
		DNS:        dns,
		Keepalive:  keepalive,
	})
	if err != nil {
		return nil, err
	}
	if err := s.syncTenantWireGuard(ctx, tenant); err != nil {
		_ = s.store.DeletePeer(ctx, peer.ID)
		return nil, err
	}
	return peer, nil
}
