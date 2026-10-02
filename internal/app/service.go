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
	"strings"

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
	PeerStats(tenantID int64) (map[string]netns.PeerStat, error)
	SyncRoutedPrefixes(tenantID int64, subnet string, prefixes []string) error
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
	// IsolationExceptions are destination IPs/CIDRs, comma-separated, that
	// stay reachable even with IsolatePeers on — see parseExceptions.
	IsolationExceptions string
}

// parseExceptions parses a comma-separated list of IPs/CIDRs into the form
// nftables rules need. A bare IP (no "/") is treated as a single host
// (/32 or /128). Returns a specific error naming exactly which entry
// didn't parse, rather than a generic "invalid exceptions" failure.
func parseExceptions(raw string) ([]*net.IPNet, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, nil
	}
	parts := strings.Split(raw, ",")
	out := make([]*net.IPNet, 0, len(parts))
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if _, ipnet, err := net.ParseCIDR(part); err == nil {
			out = append(out, ipnet)
			continue
		}
		ip := net.ParseIP(part)
		if ip == nil {
			return nil, fmt.Errorf("app: %q is not a valid IP address or CIDR", part)
		}
		bits := 32
		if ip.To4() == nil {
			bits = 128
		}
		out = append(out, &net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)})
	}
	return out, nil
}

// firewallSpecFor builds the FirewallSpec for a tenant as currently stored,
// parsing its isolation exceptions. Shared by every call site that applies
// a tenant's firewall from its persisted settings (as opposed to
// SetTenantIsolationExceptions, which validates a *new*, not-yet-stored
// value before committing it).
func firewallSpecFor(tenant *store.Tenant, subnet *net.IPNet) (netns.FirewallSpec, error) {
	exceptions, err := parseExceptions(tenant.IsolationExceptions)
	if err != nil {
		return netns.FirewallSpec{}, fmt.Errorf("app: tenant %q has an invalid stored isolation exception %q: %w", tenant.Name, tenant.IsolationExceptions, err)
	}
	return netns.FirewallSpec{WGSubnet: subnet, IsolatePeers: tenant.IsolatePeers, Exceptions: exceptions}, nil
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
	if _, err := parseExceptions(p.IsolationExceptions); err != nil {
		return nil, err
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
		Name:                p.Name,
		Subnet:              subnet.String(),
		ListenPort:          p.ListenPort,
		ServerPrivateKey:    keypair.Private.String(),
		ServerPublicKey:     keypair.Public.String(),
		DNS:                 p.DNS,
		AllowedIPs:          allowedIPs,
		Keepalive:           keepalive,
		PSKRequired:         p.PSKRequired,
		IsolatePeers:        p.IsolatePeers,
		IsolationExceptions: p.IsolationExceptions,
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
	spec, err := firewallSpecFor(tenant, subnet)
	if err != nil {
		return err
	}
	if err := s.net.ApplyFirewall(tenant.ID, spec); err != nil {
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
		if !p.Enabled {
			continue // suspended: excluded from the live interface, keys untouched
		}
		// The server always routes the peer's own address to it; its own
		// RoutedPrefixes add any further destinations on top of that (the
		// knob that actually makes this peer a gateway for a subnet behind
		// it). p.AllowedIPs plays no part here — that's what's handed to
		// the *client* to decide what it tunnels, which is an unrelated
		// setting the server-side route table must never be driven by.
		serverAllowedIPs := fmt.Sprintf("%s/32", p.Address)
		if p.RoutedPrefixes != "" {
			serverAllowedIPs += ", " + p.RoutedPrefixes
		}
		sections = append(sections, wgconf.ServerPeerSection{
			Name:         p.Name,
			PublicKey:    p.PublicKey,
			PresharedKey: p.PresharedKey,
			AllowedIPs:   serverAllowedIPs,
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

	// WireGuard's own AllowedIPs (set above) only drives its internal
	// crypto-routing — it adds nothing to the kernel's actual routing
	// table, which wg syncconf never touches (that's wg-quick's job
	// normally, and this server doesn't use wg-quick). Without this, a
	// peer's RoutedPrefixes would show up correctly in `wg show` while the
	// kernel never actually sent any matching traffic out wg0 at all —
	// found live. The peers' own addresses need no such route: the
	// subnet-wide address already assigned to wg0 creates a connected
	// route covering the whole subnet.
	routed := map[string]bool{}
	for _, p := range peers {
		if !p.Enabled || p.RoutedPrefixes == "" {
			continue
		}
		prefixes, err := parseExceptions(p.RoutedPrefixes)
		if err != nil {
			continue // already validated when stored; ignore defensively rather than fail a sync
		}
		for _, prefix := range prefixes {
			routed[prefix.String()] = true
		}
	}
	routedPrefixes := make([]string, 0, len(routed))
	for prefix := range routed {
		routedPrefixes = append(routedPrefixes, prefix)
	}
	if err := s.net.SyncRoutedPrefixes(tenant.ID, tenant.Subnet, routedPrefixes); err != nil {
		return fmt.Errorf("app: syncing routed prefixes for tenant %q: %w", tenant.Name, err)
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
		if !t.Enabled {
			continue // disabled tenants get no forwarding rule — the port goes nowhere
		}
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
		exists, err := s.net.Exists(tenant.ID)
		if err != nil {
			return fmt.Errorf("app: checking namespace for tenant %q: %w", tenant.Name, err)
		}

		if !tenant.Enabled {
			if exists {
				_ = s.net.Destroy(tenant.ID) // best-effort: bring live state in line with "disabled"
			}
			continue
		}

		subnet, err := ipam.ParseSubnet(tenant.Subnet)
		if err != nil {
			return fmt.Errorf("app: tenant %q has an invalid stored subnet %q: %w", tenant.Name, tenant.Subnet, err)
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
		spec, err := firewallSpecFor(tenant, subnet)
		if err != nil {
			return err
		}
		if err := s.net.ApplyFirewall(tenant.ID, spec); err != nil {
			return fmt.Errorf("app: reapplying firewall for tenant %q: %w", tenant.Name, err)
		}
	}
	return s.syncHostForwarding(ctx)
}

// SetTenantEnabled pauses or resumes a tenant. Disabling tears the
// namespace down entirely (no traffic in or out, no resources held) but
// never touches the database row or any peer's keys/address, so enabling
// it again brings back the identical tunnel — nothing to redistribute.
// Each direction only commits its database flag once the matching live
// action has actually succeeded, and rolls the flag back if it hasn't, so
// the stored Enabled value always matches confirmed live state (the same
// discipline DeleteTenant and CreateTenant already follow).
func (s *Service) SetTenantEnabled(ctx context.Context, tenantID int64, enabled bool) error {
	tenant, err := s.store.GetTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	if tenant.Enabled == enabled {
		return nil
	}

	if !enabled {
		if err := s.net.Destroy(tenantID); err != nil {
			return fmt.Errorf("app: disabling tenant %q: %w", tenant.Name, err)
		}
		if err := s.store.SetTenantEnabled(ctx, tenantID, false); err != nil {
			return err
		}
		return s.syncHostForwarding(ctx)
	}

	subnet, err := ipam.ParseSubnet(tenant.Subnet)
	if err != nil {
		return err
	}
	if err := s.store.SetTenantEnabled(ctx, tenantID, true); err != nil {
		return err
	}
	tenant.Enabled = true
	if err := s.bringUpTenant(ctx, tenant, subnet); err != nil {
		_ = s.store.SetTenantEnabled(ctx, tenantID, false) // it didn't actually come up
		return fmt.Errorf("app: enabling tenant %q: %w", tenant.Name, err)
	}
	return nil
}

// SetTenantIsolationExceptions replaces a tenant's isolation-exception list
// (destination IPs/CIDRs that stay reachable despite IsolatePeers) and
// re-applies its firewall immediately. Validates every entry before
// touching storage, and rolls the stored value back if applying the new
// firewall fails.
func (s *Service) SetTenantIsolationExceptions(ctx context.Context, tenantID int64, exceptions string) error {
	parsed, err := parseExceptions(exceptions)
	if err != nil {
		return err
	}
	tenant, err := s.store.GetTenant(ctx, tenantID)
	if err != nil {
		return err
	}
	subnet, err := ipam.ParseSubnet(tenant.Subnet)
	if err != nil {
		return err
	}

	previous := tenant.IsolationExceptions
	if err := s.store.SetTenantIsolationExceptions(ctx, tenantID, exceptions); err != nil {
		return err
	}
	if !tenant.Enabled {
		return nil // nothing live to re-apply to; it'll pick this up when enabled
	}
	spec := netns.FirewallSpec{WGSubnet: subnet, IsolatePeers: tenant.IsolatePeers, Exceptions: parsed}
	if err := s.net.ApplyFirewall(tenantID, spec); err != nil {
		_ = s.store.SetTenantIsolationExceptions(ctx, tenantID, previous)
		return fmt.Errorf("app: applying firewall exceptions for tenant %q: %w", tenant.Name, err)
	}
	return nil
}

// PeerStats returns live connection stats (handshake time, bytes
// transferred) for every peer currently on a tenant's WireGuard interface,
// keyed by public key. It's a direct kernel read — nothing here is stored.
func (s *Service) PeerStats(tenantID int64) (map[string]netns.PeerStat, error) {
	return s.net.PeerStats(tenantID)
}

// AllPeerStats returns live peer stats for every enabled tenant, keyed by
// tenant ID and then by peer public key — the data a cross-tenant traffic
// summary is built from. A tenant whose namespace can't be read for
// whatever reason is simply left out rather than failing the whole call:
// one tenant's hiccup shouldn't blank an operator's view of every other
// tenant's traffic.
func (s *Service) AllPeerStats(ctx context.Context) (map[int64]map[string]netns.PeerStat, error) {
	tenants, err := s.store.ListTenants(ctx)
	if err != nil {
		return nil, fmt.Errorf("app: listing tenants: %w", err)
	}
	out := make(map[int64]map[string]netns.PeerStat, len(tenants))
	for _, t := range tenants {
		if !t.Enabled {
			continue
		}
		if stats, err := s.net.PeerStats(t.ID); err == nil {
			out[t.ID] = stats
		}
	}
	return out, nil
}
