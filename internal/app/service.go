// Package app is the business-logic layer that ties together storage,
// IP allocation, WireGuard config rendering, namespace orchestration, QR
// codes, and email into the operations the TUI calls. Keeping this
// separate from the TUI means every operation here can be exercised in a
// test without a terminal or root.
package app

import (
	"context"
	"fmt"
	"net"

	"hazyvpn-server/internal/ipam"
	"hazyvpn-server/internal/mail"
	"hazyvpn-server/internal/netns"
	"hazyvpn-server/internal/store"
	"hazyvpn-server/internal/wgconf"
)

// NetManager is the subset of *netns.Manager that Service depends on,
// extracted as an interface so tests can fake namespace/firewall/WireGuard
// orchestration without root or a real network stack.
type NetManager interface {
	EnsureHostForwarding() error
	Exists(tenantID int64) (bool, error)
	Create(tenantID int64, gatewayCIDR string) error
	Destroy(tenantID int64) error
	SyncWireGuard(tenantID int64, configText string) error
	ApplyFirewall(tenantID int64, spec netns.FirewallSpec) error
	SyncHostPortForwarding(tenants []netns.HostTenantPort) error
}

// Service implements every tenant/peer operation the TUI exposes.
type Service struct {
	store      *store.Store
	net        NetManager
	publicHost string
	smtp       mail.SMTPConfig
}

// New builds a Service. publicHost is the hostname/IP peers use to reach
// this server (combined with each tenant's listen port to form its
// Endpoint); smtp configures outgoing config emails.
func New(st *store.Store, net NetManager, publicHost string, smtp mail.SMTPConfig) *Service {
	return &Service{store: st, net: net, publicHost: publicHost, smtp: smtp}
}

const (
	defaultListenPortBase = 51820
	defaultKeepalive      = 25
	defaultAllowedIPs     = "0.0.0.0/0, ::/0"
)

// --- Tenants -----------------------------------------------------------

// CreateTenantParams are the operator-facing fields for a new tenant.
// Subnet, ListenPort, DNS, AllowedIPs, and Keepalive carry sane defaults
// (see SuggestSubnet/SuggestListenPort) that the operator can override.
type CreateTenantParams struct {
	Name         string
	Subnet       string
	ListenPort   int
	DNS          string
	AllowedIPs   string
	Keepalive    int
	PSKRequired  bool
	IsolatePeers bool
}

// SuggestSubnet returns the first /24 in 10.<n>.0.0/24 (n = 0..255) not
// already used by an existing tenant. Namespaces mean two tenants could
// safely share a subnet, but suggesting distinct ones by default avoids
// operator confusion; the operator can still type in a duplicate deliberately.
func (s *Service) SuggestSubnet(ctx context.Context) (string, error) {
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return "", fmt.Errorf("app: listing tenants: %w", err)
	}
	used := make(map[string]bool, len(tenants))
	for _, t := range tenants {
		used[t.Subnet] = true
	}
	for n := 0; n <= 255; n++ {
		candidate := fmt.Sprintf("10.%d.0.0/24", n)
		if !used[candidate] {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("app: exhausted 10.0.0.0/8-based subnet suggestions, specify one manually")
}

// SuggestListenPort returns the first UDP port at or after 51820 not
// already used by another tenant. Unlike subnets, listen ports must be
// unique across tenants: the host has a single public IP, so incoming
// WireGuard traffic is dispatched to the right tenant namespace by port.
func (s *Service) SuggestListenPort(ctx context.Context) (int, error) {
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return 0, fmt.Errorf("app: listing tenants: %w", err)
	}
	used := make(map[int]bool, len(tenants))
	for _, t := range tenants {
		used[t.ListenPort] = true
	}
	for port := defaultListenPortBase; port < defaultListenPortBase+1000; port++ {
		if !used[port] {
			return port, nil
		}
	}
	return 0, fmt.Errorf("app: exhausted default listen port range, specify one manually")
}

// CreateTenant validates params, generates the tenant's server keypair,
// persists it, and brings up its namespace/WireGuard interface/firewall. If
// namespace setup fails after the database row was written, the row is
// rolled back so the tenant doesn't appear half-created.
func (s *Service) CreateTenant(ctx context.Context, p CreateTenantParams) (*store.Tenant, error) {
	subnet, err := ipam.ParseSubnet(p.Subnet)
	if err != nil {
		return nil, err
	}
	if p.ListenPort <= 0 || p.ListenPort > 65535 {
		return nil, fmt.Errorf("app: listen port %d is out of range", p.ListenPort)
	}
	if existing, err := s.store.ListTenants(ctx); err == nil {
		for _, t := range existing {
			if t.ListenPort == p.ListenPort {
				return nil, fmt.Errorf("app: listen port %d is already used by tenant %q", p.ListenPort, t.Name)
			}
		}
	}

	keypair, err := wgconf.GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("app: generating server keypair: %w", err)
	}

	allowedIPs := p.AllowedIPs
	if allowedIPs == "" {
		allowedIPs = defaultAllowedIPs
	}
	keepalive := p.Keepalive
	if keepalive <= 0 {
		keepalive = defaultKeepalive
	}

	tenant, err := s.store.CreateTenant(ctx, store.TenantInput{
		Name:             p.Name,
		Subnet:           subnet.String(),
		ListenPort:       p.ListenPort,
		ServerPrivateKey: keypair.Private.String(),
		ServerPublicKey:  keypair.Public.String(),
		DNS:              p.DNS,
		AllowedIPs:       allowedIPs,
		Keepalive:        keepalive,
		PSKRequired:      p.PSKRequired,
		IsolatePeers:     p.IsolatePeers,
	})
	if err != nil {
		return nil, err
	}

	if err := s.bringUpTenant(ctx, tenant, subnet); err != nil {
		_ = s.store.DeleteTenant(ctx, tenant.ID) // don't leave a DB-only "ghost" tenant behind
		return nil, err
	}
	return tenant, nil
}

// bringUpTenant creates the tenant's namespace, applies its (peerless, at
// creation time) WireGuard config and firewall rules, and refreshes the
// host's port-forwarding table to include it. Create itself rolls back its
// own partial work on failure, but a failure in any step *after* Create
// succeeds would otherwise leave a live, fully-networked namespace behind
// for a tenant whose database row the caller is about to delete — the
// defer below is what tears that namespace back down in that case.
func (s *Service) bringUpTenant(ctx context.Context, tenant *store.Tenant, subnet *net.IPNet) (err error) {
	ones, _ := subnet.Mask.Size()
	gatewayCIDR := fmt.Sprintf("%s/%d", ipam.GatewayAddress(subnet), ones)

	if err := s.net.Create(tenant.ID, gatewayCIDR); err != nil {
		return fmt.Errorf("app: bringing up namespace for tenant %q: %w", tenant.Name, err)
	}
	defer func() {
		if err != nil {
			_ = s.net.Destroy(tenant.ID)
		}
	}()

	if err := s.syncTenantWireGuard(ctx, tenant); err != nil {
		return err
	}
	if err := s.net.ApplyFirewall(tenant.ID, netns.FirewallSpec{WGSubnet: subnet, IsolatePeers: tenant.IsolatePeers}); err != nil {
		return fmt.Errorf("app: applying firewall for tenant %q: %w", tenant.Name, err)
	}
	if err := s.syncHostForwarding(ctx); err != nil {
		return err
	}
	return nil
}

// syncTenantWireGuard re-renders and re-applies one tenant's server-side
// WireGuard config from its current peer list — called after any peer is
// added or removed, and once at tenant creation.
func (s *Service) syncTenantWireGuard(ctx context.Context, tenant *store.Tenant) error {
	peers, err := s.store.ListPeers(ctx, tenant.ID)
	if err != nil {
		return fmt.Errorf("app: listing peers for tenant %q: %w", tenant.Name, err)
	}

	sections := make([]wgconf.ServerPeerSection, 0, len(peers))
	for _, p := range peers {
		sections = append(sections, wgconf.ServerPeerSection{
			Name:         p.Name,
			PublicKey:    p.PublicKey,
			PresharedKey: p.PresharedKey,
			AllowedIPs:   fmt.Sprintf("%s/32", p.Address),
		})
	}

	cfg := wgconf.RenderServerConfig(wgconf.ServerInterfaceConfig{
		PrivateKey: tenant.ServerPrivateKey,
		ListenPort: tenant.ListenPort,
		Peers:      sections,
	})
	if err := s.net.SyncWireGuard(tenant.ID, cfg); err != nil {
		return fmt.Errorf("app: syncing WireGuard config for tenant %q: %w", tenant.Name, err)
	}
	return nil
}

// syncHostForwarding regenerates the host's single port-forwarding table
// from the full current tenant list.
func (s *Service) syncHostForwarding(ctx context.Context) error {
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return fmt.Errorf("app: listing tenants: %w", err)
	}
	ports := make([]netns.HostTenantPort, 0, len(tenants))
	for _, t := range tenants {
		ports = append(ports, netns.HostTenantPort{TenantID: t.ID, ListenPort: t.ListenPort})
	}
	if err := s.net.SyncHostPortForwarding(ports); err != nil {
		return fmt.Errorf("app: syncing host port forwarding: %w", err)
	}
	return nil
}

// DeleteTenant tears down a tenant's namespace and removes it (and its
// peers, via cascade) from storage. The database row is only removed once
// the namespace is confirmed torn down, so a failed teardown leaves
// something to investigate rather than silently losing records.
func (s *Service) DeleteTenant(ctx context.Context, id int64) error {
	if err := s.net.Destroy(id); err != nil {
		return fmt.Errorf("app: tearing down namespace: %w", err)
	}
	if err := s.store.DeleteTenant(ctx, id); err != nil {
		return err
	}
	return s.syncHostForwarding(ctx)
}

func (s *Service) ListTenants(ctx context.Context) ([]store.Tenant, error) {
	return s.store.ListTenants(ctx)
}

// Reconcile brings every tenant in the database up to a live, correctly
// configured namespace. It's called once at startup (both in daemon mode
// and before the TUI runs standalone) because namespaces are kernel state
// tied to the container's lifetime: a container restart wipes every
// namespace even though the database, on a volume, survives untouched. For
// a tenant whose namespace already exists (the server process restarted
// without the container restarting), Reconcile only re-syncs its
// WireGuard config and firewall rather than recreating anything.
func (s *Service) Reconcile(ctx context.Context) error {
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return fmt.Errorf("app: listing tenants: %w", err)
	}

	for i := range tenants {
		tenant := &tenants[i]
		subnet, err := ipam.ParseSubnet(tenant.Subnet)
		if err != nil {
			return fmt.Errorf("app: tenant %q has an invalid stored subnet %q: %w", tenant.Name, tenant.Subnet, err)
		}

		exists, err := s.net.Exists(tenant.ID)
		if err != nil {
			return fmt.Errorf("app: checking namespace for tenant %q: %w", tenant.Name, err)
		}
		if !exists {
			ones, _ := subnet.Mask.Size()
			gatewayCIDR := fmt.Sprintf("%s/%d", ipam.GatewayAddress(subnet), ones)
			if err := s.net.Create(tenant.ID, gatewayCIDR); err != nil {
				return fmt.Errorf("app: recreating namespace for tenant %q: %w", tenant.Name, err)
			}
		}
		if err := s.syncTenantWireGuard(ctx, tenant); err != nil {
			return err
		}
		if err := s.net.ApplyFirewall(tenant.ID, netns.FirewallSpec{WGSubnet: subnet, IsolatePeers: tenant.IsolatePeers}); err != nil {
			return fmt.Errorf("app: reapplying firewall for tenant %q: %w", tenant.Name, err)
		}
	}
	return s.syncHostForwarding(ctx)
}
