package app

import (
	"context"
	"encoding/json"
	"fmt"

	"hazyvpn-server/internal/ipam"
	"hazyvpn-server/internal/store"
)

// TenantBackup is a full, restorable snapshot of one tenant: its settings
// and every peer's keys and address. It contains private keys in plaintext
// JSON, so operators should handle backup files like any other secret.
type TenantBackup struct {
	Tenant store.TenantInput `json:"tenant"`
	Peers  []store.PeerInput `json:"peers"`
}

// ExportTenantBackup serializes a tenant and all of its peers to JSON.
func (s *Service) ExportTenantBackup(ctx context.Context, tenantID int64) ([]byte, error) {
	tenant, err := s.store.GetTenant(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	peers, err := s.store.ListPeers(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	backup := TenantBackup{
		Tenant: store.TenantInput{
			Name: tenant.Name, Subnet: tenant.Subnet, ListenPort: tenant.ListenPort,
			ServerPrivateKey: tenant.ServerPrivateKey, ServerPublicKey: tenant.ServerPublicKey,
			DNS: tenant.DNS, AllowedIPs: tenant.AllowedIPs, Keepalive: tenant.Keepalive,
			PSKRequired: tenant.PSKRequired, IsolatePeers: tenant.IsolatePeers,
		},
	}
	for _, p := range peers {
		backup.Peers = append(backup.Peers, store.PeerInput{
			Name: p.Name, Address: p.Address, PublicKey: p.PublicKey,
			PrivateKey: p.PrivateKey, PresharedKey: p.PresharedKey,
			AllowedIPs: p.AllowedIPs, DNS: p.DNS, Keepalive: p.Keepalive,
		})
	}

	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("app: encoding backup: %w", err)
	}
	return data, nil
}

// ImportTenantBackup restores a TenantBackup as a brand-new tenant,
// preserving every original key, address, and setting (so already-handed-out
// peer configs keep working), then brings up its namespace exactly like a
// freshly created tenant.
func (s *Service) ImportTenantBackup(ctx context.Context, data []byte, newName string) (*store.Tenant, error) {
	var backup TenantBackup
	if err := json.Unmarshal(data, &backup); err != nil {
		return nil, fmt.Errorf("app: decoding backup: %w", err)
	}
	if newName != "" {
		backup.Tenant.Name = newName
	}

	subnet, err := ipam.ParseSubnet(backup.Tenant.Subnet)
	if err != nil {
		return nil, err
	}

	tenant, err := s.store.CreateTenant(ctx, backup.Tenant)
	if err != nil {
		return nil, err
	}

	for _, p := range backup.Peers {
		p.TenantID = tenant.ID
		if _, err := s.store.CreatePeer(ctx, p); err != nil {
			_ = s.store.DeleteTenant(ctx, tenant.ID)
			return nil, fmt.Errorf("app: restoring peer %q: %w", p.Name, err)
		}
	}

	if err := s.bringUpTenant(ctx, tenant, subnet); err != nil {
		_ = s.store.DeleteTenant(ctx, tenant.ID)
		return nil, err
	}
	return tenant, nil
}
