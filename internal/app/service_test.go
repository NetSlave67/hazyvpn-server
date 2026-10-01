package app

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"hazyvpn-server/internal/cryptutil"
	"hazyvpn-server/internal/mail"
	"hazyvpn-server/internal/netns"
	"hazyvpn-server/internal/store"
)

// fakeNet is a NetManager that records calls and can be told to fail a
// named method, so Service's rollback-on-failure logic can be exercised
// without root or a real network namespace.
type fakeNet struct {
	createCalls   []int64
	destroyCalls  []int64
	syncCalls     []int64
	firewallCalls []int64
	hostSyncs     [][]netns.HostTenantPort
	failMethod    string
	existing      map[int64]bool // tenants whose namespace Exists should report true
}

func (f *fakeNet) EnsureHostForwarding() error { return nil }

func (f *fakeNet) Exists(tenantID int64) (bool, error) {
	return f.existing[tenantID], nil
}

func (f *fakeNet) Create(tenantID int64, gatewayCIDR string) error {
	f.createCalls = append(f.createCalls, tenantID)
	if f.failMethod == "Create" {
		return fmt.Errorf("fakeNet: injected Create failure")
	}
	return nil
}

func (f *fakeNet) Destroy(tenantID int64) error {
	f.destroyCalls = append(f.destroyCalls, tenantID)
	if f.failMethod == "Destroy" {
		return fmt.Errorf("fakeNet: injected Destroy failure")
	}
	return nil
}

func (f *fakeNet) SyncWireGuard(tenantID int64, configText string) error {
	f.syncCalls = append(f.syncCalls, tenantID)
	if f.failMethod == "SyncWireGuard" {
		return fmt.Errorf("fakeNet: injected SyncWireGuard failure")
	}
	return nil
}

func (f *fakeNet) ApplyFirewall(tenantID int64, spec netns.FirewallSpec) error {
	f.firewallCalls = append(f.firewallCalls, tenantID)
	if f.failMethod == "ApplyFirewall" {
		return fmt.Errorf("fakeNet: injected ApplyFirewall failure")
	}
	return nil
}

func (f *fakeNet) SyncHostPortForwarding(tenants []netns.HostTenantPort) error {
	f.hostSyncs = append(f.hostSyncs, tenants)
	return nil
}

func newTestService(t *testing.T, net *fakeNet) (*Service, *store.Store) {
	t.Helper()
	var key [cryptutil.KeySize]byte
	sealer := cryptutil.NewSealer(key)
	st, err := store.Open(filepath.Join(t.TempDir(), "test.sqlite"), sealer)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	svc := New(st, net, "vpn.example.net", mail.SMTPConfig{})
	return svc, st
}

func TestCreateTenantBringsUpNamespace(t *testing.T) {
	fn := &fakeNet{}
	svc, _ := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{
		Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820,
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if len(fn.createCalls) != 1 || fn.createCalls[0] != tenant.ID {
		t.Fatalf("expected Create to be called once for tenant %d, got %v", tenant.ID, fn.createCalls)
	}
	if len(fn.syncCalls) != 1 {
		t.Fatalf("expected one SyncWireGuard call, got %d", len(fn.syncCalls))
	}
	if len(fn.firewallCalls) != 1 {
		t.Fatalf("expected one ApplyFirewall call, got %d", len(fn.firewallCalls))
	}
	if len(fn.hostSyncs) != 1 || len(fn.hostSyncs[0]) != 1 {
		t.Fatalf("expected host port forwarding to include the new tenant, got %v", fn.hostSyncs)
	}
}

func TestCreateTenantRollsBackDBRowOnNamespaceFailure(t *testing.T) {
	fn := &fakeNet{failMethod: "Create"}
	svc, st := newTestService(t, fn)
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, CreateTenantParams{
		Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820,
	})
	if err == nil {
		t.Fatal("expected CreateTenant to surface the namespace failure")
	}
	tenants, err := st.ListTenants(ctx)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(tenants) != 0 {
		t.Fatalf("expected the DB row to be rolled back, found %d tenants", len(tenants))
	}
}

// TestCreateTenantDestroysNamespaceWhenAStepAfterCreateFails guards against
// a real bug found in production: Create() itself rolls back its own
// partial work, but a tenant whose namespace came up fine and then failed
// a later step (WireGuard sync, firewall, host forwarding) was being left
// as a live, fully-networked orphan namespace while its DB row got deleted
// out from under it.
func TestCreateTenantDestroysNamespaceWhenAStepAfterCreateFails(t *testing.T) {
	fn := &fakeNet{failMethod: "SyncWireGuard"}
	svc, st := newTestService(t, fn)
	ctx := context.Background()

	_, err := svc.CreateTenant(ctx, CreateTenantParams{
		Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820,
	})
	if err == nil {
		t.Fatal("expected CreateTenant to surface the WireGuard sync failure")
	}
	if len(fn.destroyCalls) != 1 {
		t.Fatalf("expected the namespace to be destroyed after the later step failed, got %d Destroy calls", len(fn.destroyCalls))
	}
	tenants, err := st.ListTenants(ctx)
	if err != nil {
		t.Fatalf("ListTenants: %v", err)
	}
	if len(tenants) != 0 {
		t.Fatalf("expected the DB row to be rolled back, found %d tenants", len(tenants))
	}
}

func TestCreateTenantRejectsDuplicateListenPort(t *testing.T) {
	fn := &fakeNet{}
	svc, _ := newTestService(t, fn)
	ctx := context.Background()

	if _, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "a", Subnet: "10.1.0.0/24", ListenPort: 51820}); err != nil {
		t.Fatalf("CreateTenant(a): %v", err)
	}
	_, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "b", Subnet: "10.2.0.0/24", ListenPort: 51820})
	if err == nil {
		t.Fatal("expected an error when reusing a listen port across tenants")
	}
}

func TestSuggestSubnetSkipsUsedOnes(t *testing.T) {
	fn := &fakeNet{}
	svc, _ := newTestService(t, fn)
	ctx := context.Background()

	first, err := svc.SuggestSubnet(ctx)
	if err != nil {
		t.Fatalf("SuggestSubnet: %v", err)
	}
	if first != "10.0.0.0/24" {
		t.Fatalf("SuggestSubnet = %q, want 10.0.0.0/24", first)
	}

	if _, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "a", Subnet: first, ListenPort: 51820}); err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	second, err := svc.SuggestSubnet(ctx)
	if err != nil {
		t.Fatalf("SuggestSubnet (2nd): %v", err)
	}
	if second == first {
		t.Fatalf("SuggestSubnet returned the same subnet twice: %q", second)
	}
}

func TestAddPeerAutoAssignsAndRejectsDuplicateAddress(t *testing.T) {
	fn := &fakeNet{}
	svc, _ := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	alice, err := svc.AddPeer(ctx, AddPeerParams{TenantID: tenant.ID, Name: "alice"})
	if err != nil {
		t.Fatalf("AddPeer(alice): %v", err)
	}
	if alice.Address != "10.8.0.2" {
		t.Fatalf("alice.Address = %q, want 10.8.0.2 (first free after gateway .1)", alice.Address)
	}

	// Bob explicitly asks for alice's address -> must be rejected with a
	// specific, actionable error, not a generic failure.
	_, err = svc.AddPeer(ctx, AddPeerParams{TenantID: tenant.ID, Name: "bob", Address: "10.8.0.2"})
	if err == nil {
		t.Fatal("expected an error when bob requests alice's already-used address")
	}

	// Carol doesn't specify an address -> must auto-skip alice's.
	carol, err := svc.AddPeer(ctx, AddPeerParams{TenantID: tenant.ID, Name: "carol"})
	if err != nil {
		t.Fatalf("AddPeer(carol): %v", err)
	}
	if carol.Address != "10.8.0.3" {
		t.Fatalf("carol.Address = %q, want 10.8.0.3", carol.Address)
	}
}

func TestAddPeerPushesConfigToLiveInterface(t *testing.T) {
	fn := &fakeNet{}
	svc, _ := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	beforeSyncs := len(fn.syncCalls)

	if _, err := svc.AddPeer(ctx, AddPeerParams{TenantID: tenant.ID, Name: "alice"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if len(fn.syncCalls) != beforeSyncs+1 {
		t.Fatalf("expected AddPeer to trigger exactly one more SyncWireGuard call")
	}
}

func TestPeerConfigTextRendersFullTunnel(t *testing.T) {
	fn := &fakeNet{}
	svc, _ := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	peer, err := svc.AddPeer(ctx, AddPeerParams{TenantID: tenant.ID, Name: "alice"})
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	text, err := svc.PeerConfigText(ctx, tenant.ID, peer.ID)
	if err != nil {
		t.Fatalf("PeerConfigText: %v", err)
	}
	if !containsAll(text, "PrivateKey", "10.8.0.2/24", "vpn.example.net:51820", tenant.ServerPublicKey) {
		t.Fatalf("rendered config missing expected fields:\n%s", text)
	}
}

func TestImportPeerConfigRefusesDangerousHooks(t *testing.T) {
	fn := &fakeNet{}
	svc, _ := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	malicious := "[Interface]\nPrivateKey = cEhBpuZuKkIkbaw1xMkXz4jfM+2KrTl4p5LWIPgAfxQ=\n" +
		"Address = 10.8.0.5/24\nPostUp = iptables -I INPUT -j ACCEPT\n"
	_, err = svc.ImportPeerConfig(ctx, tenant.ID, "malicious", malicious)
	if err == nil {
		t.Fatal("expected ImportPeerConfig to refuse a config with a PostUp hook")
	}
}

func TestExportImportTenantBackupRoundTrip(t *testing.T) {
	fn := &fakeNet{}
	svc, _ := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if _, err := svc.AddPeer(ctx, AddPeerParams{TenantID: tenant.ID, Name: "alice"}); err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	data, err := svc.ExportTenantBackup(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("ExportTenantBackup: %v", err)
	}

	restored, err := svc.ImportTenantBackup(ctx, data, "acme-restored")
	if err != nil {
		t.Fatalf("ImportTenantBackup: %v", err)
	}
	peers, err := svc.ListPeers(ctx, restored.ID)
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	if len(peers) != 1 || peers[0].Name != "alice" || peers[0].Address != "10.8.0.2" {
		t.Fatalf("restored peers = %+v, want alice at 10.8.0.2", peers)
	}
}

func TestReconcileRecreatesMissingNamespacesOnly(t *testing.T) {
	fn := &fakeNet{}
	svc, _ := newTestService(t, fn)
	ctx := context.Background()

	a, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "a", Subnet: "10.1.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant(a): %v", err)
	}
	b, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "b", Subnet: "10.2.0.0/24", ListenPort: 51821})
	if err != nil {
		t.Fatalf("CreateTenant(b): %v", err)
	}

	// Simulate a container restart: namespace "a" survived (process restart
	// without container restart), namespace "b" did not.
	fn.existing = map[int64]bool{a.ID: true}
	fn.createCalls = nil
	fn.syncCalls = nil
	fn.firewallCalls = nil

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if len(fn.createCalls) != 1 || fn.createCalls[0] != b.ID {
		t.Fatalf("expected Create to be called only for tenant b (%d), got %v", b.ID, fn.createCalls)
	}
	if len(fn.syncCalls) != 2 {
		t.Fatalf("expected WireGuard config to be re-synced for both tenants, got %d calls", len(fn.syncCalls))
	}
	if len(fn.firewallCalls) != 2 {
		t.Fatalf("expected firewall rules to be reapplied for both tenants, got %d calls", len(fn.firewallCalls))
	}
}

func containsAll(haystack string, needles ...string) bool {
	for _, n := range needles {
		if !strings.Contains(haystack, n) {
			return false
		}
	}
	return true
}
