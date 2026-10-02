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
	createCalls       []int64
	destroyCalls      []int64
	syncCalls         []int64
	syncConfigs       []string // rendered config text, same order as syncCalls
	firewallCalls     []int64
	firewallSpecs     []netns.FirewallSpec // specs passed to ApplyFirewall, same order as firewallCalls
	hostSyncs         [][]netns.HostTenantPort
	failMethod        string
	existing          map[int64]bool // tenants whose namespace Exists should report true
	stats             map[string]netns.PeerStat
	statsErr          error
	statsErrFor       map[int64]bool // tenant IDs whose PeerStats call should fail specifically
	routedPrefixCalls [][]string     // prefixes passed to each SyncRoutedPrefixes call, in order
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
	f.syncConfigs = append(f.syncConfigs, configText)
	if f.failMethod == "SyncWireGuard" {
		return fmt.Errorf("fakeNet: injected SyncWireGuard failure")
	}
	return nil
}

func (f *fakeNet) ApplyFirewall(tenantID int64, spec netns.FirewallSpec) error {
	f.firewallCalls = append(f.firewallCalls, tenantID)
	f.firewallSpecs = append(f.firewallSpecs, spec)
	if f.failMethod == "ApplyFirewall" {
		return fmt.Errorf("fakeNet: injected ApplyFirewall failure")
	}
	return nil
}

func (f *fakeNet) SyncHostPortForwarding(tenants []netns.HostTenantPort) error {
	f.hostSyncs = append(f.hostSyncs, tenants)
	return nil
}

func (f *fakeNet) PeerStats(tenantID int64) (map[string]netns.PeerStat, error) {
	if f.statsErrFor[tenantID] {
		return nil, fmt.Errorf("fakeNet: injected PeerStats failure for tenant %d", tenantID)
	}
	if f.statsErr != nil {
		return nil, f.statsErr
	}
	return f.stats, nil
}

func (f *fakeNet) SyncRoutedPrefixes(tenantID int64, subnet string, prefixes []string) error {
	f.routedPrefixCalls = append(f.routedPrefixCalls, prefixes)
	if f.failMethod == "SyncRoutedPrefixes" {
		return fmt.Errorf("fakeNet: injected SyncRoutedPrefixes failure")
	}
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

	restored, err := svc.ImportTenantBackup(ctx, data, "acme-restored", 51821)
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

// TestImportTenantBackupRejectsListenPortCollision guards against a real
// bug found in production: restoring a backup alongside its still-live
// original (same listen port, different name) silently left two tenants
// sharing one DNAT rule — the host could only route that port to one of
// them, and the TUI gave no indication which tenant lost. The original
// name collision was always caught; the listen-port collision was not.
func TestImportTenantBackupRejectsListenPortCollision(t *testing.T) {
	fn := &fakeNet{}
	svc, _ := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	data, err := svc.ExportTenantBackup(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("ExportTenantBackup: %v", err)
	}

	// New name, but the backup's listen port (51820) is still in use by
	// the live "acme" tenant — must be rejected, not silently accepted.
	_, err = svc.ImportTenantBackup(ctx, data, "acme-clone", 0)
	if err == nil {
		t.Fatal("expected ImportTenantBackup to reject a colliding listen port")
	}

	// Explicitly providing a free port must succeed.
	restored, err := svc.ImportTenantBackup(ctx, data, "acme-clone", 51821)
	if err != nil {
		t.Fatalf("ImportTenantBackup with a free port: %v", err)
	}
	if restored.ListenPort != 51821 {
		t.Fatalf("restored.ListenPort = %d, want 51821", restored.ListenPort)
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

func TestSetTenantEnabledFalseDestroysNamespaceAndExcludesFromForwarding(t *testing.T) {
	fn := &fakeNet{}
	svc, st := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	if err := svc.SetTenantEnabled(ctx, tenant.ID, false); err != nil {
		t.Fatalf("SetTenantEnabled(false): %v", err)
	}
	if len(fn.destroyCalls) != 1 || fn.destroyCalls[0] != tenant.ID {
		t.Fatalf("expected Destroy to be called for tenant %d, got %v", tenant.ID, fn.destroyCalls)
	}
	got, err := st.GetTenant(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.Enabled {
		t.Fatal("expected tenant to be disabled in storage")
	}
	lastHostSync := fn.hostSyncs[len(fn.hostSyncs)-1]
	for _, p := range lastHostSync {
		if p.TenantID == tenant.ID {
			t.Fatalf("expected disabled tenant to be excluded from host forwarding, found %+v", p)
		}
	}
}

func TestSetTenantEnabledFalseRollsBackOnDestroyFailure(t *testing.T) {
	fn := &fakeNet{}
	svc, st := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	fn.failMethod = "Destroy"
	if err := svc.SetTenantEnabled(ctx, tenant.ID, false); err == nil {
		t.Fatal("expected SetTenantEnabled(false) to surface the Destroy failure")
	}
	got, err := st.GetTenant(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if !got.Enabled {
		t.Fatal("tenant must remain enabled in storage when the namespace could not actually be torn down")
	}
}

func TestSetTenantEnabledTrueBringsNamespaceBackUpUnchanged(t *testing.T) {
	fn := &fakeNet{}
	svc, st := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	originalPublicKey := tenant.ServerPublicKey

	if err := svc.SetTenantEnabled(ctx, tenant.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	fn.createCalls = nil
	if err := svc.SetTenantEnabled(ctx, tenant.ID, true); err != nil {
		t.Fatalf("re-enable: %v", err)
	}
	if len(fn.createCalls) != 1 || fn.createCalls[0] != tenant.ID {
		t.Fatalf("expected Create to be called once for the re-enabled tenant, got %v", fn.createCalls)
	}
	got, err := st.GetTenant(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if !got.Enabled {
		t.Fatal("expected tenant to be enabled again in storage")
	}
	if got.ServerPublicKey != originalPublicKey {
		t.Fatalf("re-enabling must not regenerate keys: got %q, want %q", got.ServerPublicKey, originalPublicKey)
	}
}

func TestSetTenantEnabledIsIdempotent(t *testing.T) {
	fn := &fakeNet{}
	svc, _ := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	fn.createCalls = nil
	if err := svc.SetTenantEnabled(ctx, tenant.ID, true); err != nil {
		t.Fatalf("SetTenantEnabled(true) on an already-enabled tenant: %v", err)
	}
	if len(fn.createCalls) != 0 {
		t.Fatalf("expected no namespace churn for a no-op enable, got %v", fn.createCalls)
	}
}

func TestSetPeerEnabledExcludesFromLiveConfig(t *testing.T) {
	fn := &fakeNet{}
	svc, st := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	peer, err := svc.AddPeer(ctx, AddPeerParams{TenantID: tenant.ID, Name: "alice"})
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	originalPrivateKey := peer.PrivateKey

	if err := svc.SetPeerEnabled(ctx, tenant.ID, peer.ID, false); err != nil {
		t.Fatalf("SetPeerEnabled(false): %v", err)
	}
	got, err := st.GetPeer(ctx, peer.ID)
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if got.Enabled {
		t.Fatal("expected peer to be disabled in storage")
	}
	if got.PrivateKey != originalPrivateKey {
		t.Fatal("disabling a peer must not touch its keys")
	}

	if err := svc.SetPeerEnabled(ctx, tenant.ID, peer.ID, true); err != nil {
		t.Fatalf("SetPeerEnabled(true): %v", err)
	}
	got, err = st.GetPeer(ctx, peer.ID)
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if !got.Enabled {
		t.Fatal("expected peer to be re-enabled in storage")
	}
	if got.PrivateKey != originalPrivateKey {
		t.Fatal("re-enabling a peer must not regenerate its keys")
	}
}

func TestSetTenantIsolationExceptionsValidatesBeforeStoring(t *testing.T) {
	fn := &fakeNet{}
	svc, st := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820, IsolatePeers: true})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	if err := svc.SetTenantIsolationExceptions(ctx, tenant.ID, "not-an-ip"); err == nil {
		t.Fatal("expected a garbage exception entry to be rejected")
	}
	got, err := st.GetTenant(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.IsolationExceptions != "" {
		t.Fatalf("a rejected exceptions update must not be stored, got %q", got.IsolationExceptions)
	}
}

func TestSetTenantIsolationExceptionsAppliesToLiveFirewall(t *testing.T) {
	fn := &fakeNet{}
	svc, st := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820, IsolatePeers: true})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	if err := svc.SetTenantIsolationExceptions(ctx, tenant.ID, "10.8.0.5"); err != nil {
		t.Fatalf("SetTenantIsolationExceptions: %v", err)
	}
	got, err := st.GetTenant(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.IsolationExceptions != "10.8.0.5" {
		t.Fatalf("IsolationExceptions = %q, want %q", got.IsolationExceptions, "10.8.0.5")
	}
	lastSpec := fn.firewallSpecs[len(fn.firewallSpecs)-1]
	if len(lastSpec.Exceptions) != 1 || lastSpec.Exceptions[0].String() != "10.8.0.5/32" {
		t.Fatalf("expected the applied firewall spec to carry the new exception, got %+v", lastSpec.Exceptions)
	}
}

func TestSetTenantIsolationExceptionsRollsBackOnApplyFailure(t *testing.T) {
	fn := &fakeNet{}
	svc, st := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820, IsolatePeers: true})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	fn.failMethod = "ApplyFirewall"
	if err := svc.SetTenantIsolationExceptions(ctx, tenant.ID, "10.8.0.5"); err == nil {
		t.Fatal("expected the ApplyFirewall failure to surface")
	}
	got, err := st.GetTenant(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.IsolationExceptions != "" {
		t.Fatalf("expected the exceptions update to be rolled back, got %q", got.IsolationExceptions)
	}
}

func TestReconcileSkipsDisabledTenants(t *testing.T) {
	fn := &fakeNet{}
	svc, _ := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if err := svc.SetTenantEnabled(ctx, tenant.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}

	fn.createCalls = nil
	fn.syncCalls = nil
	fn.firewallCalls = nil
	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(fn.createCalls) != 0 || len(fn.syncCalls) != 0 || len(fn.firewallCalls) != 0 {
		t.Fatalf("expected Reconcile to skip a disabled tenant entirely, got create=%v sync=%v firewall=%v",
			fn.createCalls, fn.syncCalls, fn.firewallCalls)
	}
}

// TestReconcileTearsDownStaleNamespaceForDisabledTenant covers a disabled
// tenant whose namespace is still (unexpectedly) up — e.g. a previous
// disable's Destroy call silently failed, or state was edited directly in
// the database. Reconcile should notice and finish the job rather than
// leaving a supposedly-disabled tenant quietly still serving traffic.
func TestReconcileTearsDownStaleNamespaceForDisabledTenant(t *testing.T) {
	fn := &fakeNet{}
	svc, _ := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if err := svc.SetTenantEnabled(ctx, tenant.ID, false); err != nil {
		t.Fatalf("disable: %v", err)
	}
	fn.destroyCalls = nil
	fn.existing = map[int64]bool{tenant.ID: true} // simulate the namespace somehow still being up

	if err := svc.Reconcile(ctx); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if len(fn.destroyCalls) != 1 || fn.destroyCalls[0] != tenant.ID {
		t.Fatalf("expected Reconcile to destroy the stale namespace of a disabled tenant, got %v", fn.destroyCalls)
	}
}

func TestPeerStatsPassesThroughToNetManager(t *testing.T) {
	fn := &fakeNet{stats: map[string]netns.PeerStat{"abc": {RxBytes: 42}}}
	svc, _ := newTestService(t, fn)

	stats, err := svc.PeerStats(1)
	if err != nil {
		t.Fatalf("PeerStats: %v", err)
	}
	if stats["abc"].RxBytes != 42 {
		t.Fatalf("PeerStats = %+v, want RxBytes 42", stats)
	}
}

// TestServerConfigRoutesOwnAddressPlusRoutedPrefixes guards a real design
// gap found live: the server's own per-peer AllowedIPs used to be
// hardcoded to the peer's own /32, completely ignoring any per-peer
// routing the operator might want — there was no way to make the server
// route an extra prefix (e.g. a subnet behind a peer acting as a gateway)
// to a specific peer at all. RoutedPrefixes is additive to the peer's own
// address, never a replacement for it.
func TestServerConfigRoutesOwnAddressPlusRoutedPrefixes(t *testing.T) {
	fn := &fakeNet{}
	svc, st := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	peer, err := svc.AddPeer(ctx, AddPeerParams{TenantID: tenant.ID, Name: "gateway"})
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if err := svc.UpdatePeerRouting(ctx, tenant.ID, peer.ID, "0.0.0.0/0, ::/0", "192.168.50.0/24"); err != nil {
		t.Fatalf("UpdatePeerRouting: %v", err)
	}

	lastConfig := fn.syncConfigs[len(fn.syncConfigs)-1]
	if !strings.Contains(lastConfig, "10.8.0.2/32, 192.168.50.0/24") {
		t.Fatalf("expected the peer's own /32 plus its routed prefix in the server config, got:\n%s", lastConfig)
	}

	got, err := st.GetPeer(ctx, peer.ID)
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if got.AllowedIPs != "0.0.0.0/0, ::/0" {
		t.Fatalf("client-facing AllowedIPs = %q, want the full-tunnel value unchanged by routing", got.AllowedIPs)
	}
}

// TestSyncTenantWireGuardSyncsKernelRoutesForRoutedPrefixes guards a real
// bug found live: WireGuard's own AllowedIPs (synced above) only drives its
// internal crypto-routing, never the kernel's actual routing table — that's
// wg-quick's job normally, which this server never uses. Without an
// explicit SyncRoutedPrefixes call, a peer's RoutedPrefixes would show up
// correctly in `wg show` while the kernel never routed a single packet
// there.
func TestSyncTenantWireGuardSyncsKernelRoutesForRoutedPrefixes(t *testing.T) {
	fn := &fakeNet{}
	svc, _ := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	peer, err := svc.AddPeer(ctx, AddPeerParams{TenantID: tenant.ID, Name: "gateway"})
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	if err := svc.UpdatePeerRouting(ctx, tenant.ID, peer.ID, "0.0.0.0/0", "192.168.50.0/24"); err != nil {
		t.Fatalf("UpdatePeerRouting: %v", err)
	}
	last := fn.routedPrefixCalls[len(fn.routedPrefixCalls)-1]
	if len(last) != 1 || last[0] != "192.168.50.0/24" {
		t.Fatalf("expected SyncRoutedPrefixes to be called with [192.168.50.0/24], got %v", last)
	}

	// Clearing it back out must also sync an empty set, not just skip the
	// call — otherwise a stale kernel route would be left behind forever.
	if err := svc.UpdatePeerRouting(ctx, tenant.ID, peer.ID, "0.0.0.0/0", ""); err != nil {
		t.Fatalf("UpdatePeerRouting (clear): %v", err)
	}
	last = fn.routedPrefixCalls[len(fn.routedPrefixCalls)-1]
	if len(last) != 0 {
		t.Fatalf("expected SyncRoutedPrefixes to be called with an empty set after clearing, got %v", last)
	}
}

func TestSyncTenantWireGuardExcludesDisabledPeersFromRoutedPrefixes(t *testing.T) {
	fn := &fakeNet{}
	svc, _ := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	peer, err := svc.AddPeer(ctx, AddPeerParams{TenantID: tenant.ID, Name: "gateway"})
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}
	if err := svc.UpdatePeerRouting(ctx, tenant.ID, peer.ID, "0.0.0.0/0", "192.168.50.0/24"); err != nil {
		t.Fatalf("UpdatePeerRouting: %v", err)
	}

	if err := svc.SetPeerEnabled(ctx, tenant.ID, peer.ID, false); err != nil {
		t.Fatalf("SetPeerEnabled(false): %v", err)
	}
	last := fn.routedPrefixCalls[len(fn.routedPrefixCalls)-1]
	if len(last) != 0 {
		t.Fatalf("expected a disabled peer's routed prefixes to be excluded, got %v", last)
	}
}

func TestUpdatePeerRoutingRejectsEmptyAllowedIPs(t *testing.T) {
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

	if err := svc.UpdatePeerRouting(ctx, tenant.ID, peer.ID, "", "10.0.0.0/8"); err == nil {
		t.Fatal("expected empty AllowedIPs to be rejected — a peer always needs something to tunnel")
	}
}

func TestUpdatePeerRoutingRejectsGarbageRoutedPrefix(t *testing.T) {
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

	if err := svc.UpdatePeerRouting(ctx, tenant.ID, peer.ID, "0.0.0.0/0", "not-a-cidr"); err == nil {
		t.Fatal("expected a garbage routed-prefix entry to be rejected")
	}
}

func TestUpdatePeerRoutingSkipsResyncWhenOnlyAllowedIPsChanges(t *testing.T) {
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
	before := len(fn.syncCalls)

	if err := svc.UpdatePeerRouting(ctx, tenant.ID, peer.ID, "10.8.0.0/24", ""); err != nil {
		t.Fatalf("UpdatePeerRouting: %v", err)
	}
	if len(fn.syncCalls) != before {
		t.Fatalf("expected no WireGuard resync when RoutedPrefixes is unchanged, got %d new calls", len(fn.syncCalls)-before)
	}
}

func TestUpdatePeerRoutingRollsBackOnSyncFailure(t *testing.T) {
	fn := &fakeNet{}
	svc, st := newTestService(t, fn)
	ctx := context.Background()

	tenant, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	peer, err := svc.AddPeer(ctx, AddPeerParams{TenantID: tenant.ID, Name: "alice"})
	if err != nil {
		t.Fatalf("AddPeer: %v", err)
	}

	fn.failMethod = "SyncWireGuard"
	if err := svc.UpdatePeerRouting(ctx, tenant.ID, peer.ID, "0.0.0.0/0", "192.168.50.0/24"); err == nil {
		t.Fatal("expected the SyncWireGuard failure to surface")
	}
	got, err := st.GetPeer(ctx, peer.ID)
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if got.RoutedPrefixes != "" {
		t.Fatalf("expected RoutedPrefixes to be rolled back to empty, got %q", got.RoutedPrefixes)
	}
}

func TestAllPeerStatsExcludesDisabledTenantsAndFailures(t *testing.T) {
	fn := &fakeNet{stats: map[string]netns.PeerStat{"abc": {RxBytes: 42}}}
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
	c, err := svc.CreateTenant(ctx, CreateTenantParams{Name: "c", Subnet: "10.3.0.0/24", ListenPort: 51822})
	if err != nil {
		t.Fatalf("CreateTenant(c): %v", err)
	}
	if err := svc.SetTenantEnabled(ctx, b.ID, false); err != nil {
		t.Fatalf("disable b: %v", err)
	}
	fn.statsErrFor = map[int64]bool{c.ID: true} // simulate a namespace read hiccup for c

	all, err := svc.AllPeerStats(ctx)
	if err != nil {
		t.Fatalf("AllPeerStats: %v", err)
	}
	if _, ok := all[a.ID]; !ok {
		t.Fatal("expected stats for enabled, readable tenant a")
	}
	if _, ok := all[b.ID]; ok {
		t.Fatal("did not expect stats for disabled tenant b")
	}
	if _, ok := all[c.ID]; ok {
		t.Fatal("expected tenant c's PeerStats failure to just be omitted, not surfaced as a whole-call error")
	}
	if all[a.ID]["abc"].RxBytes != 42 {
		t.Fatalf("stats for tenant a = %+v, want RxBytes 42 for peer abc", all[a.ID])
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
