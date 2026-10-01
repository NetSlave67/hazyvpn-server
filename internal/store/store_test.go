package store

import (
	"context"
	"database/sql"
	"net"
	"path/filepath"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"hazyvpn-server/internal/cryptutil"
	"hazyvpn-server/internal/ipam"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	var key [cryptutil.KeySize]byte
	sealer := cryptutil.NewSealer(key)
	s, err := Open(filepath.Join(t.TempDir(), "test.sqlite"), sealer)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func TestCreateAndGetTenantRoundTripsPrivateKey(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	tenant, err := s.CreateTenant(ctx, TenantInput{
		Name:             "acme",
		Subnet:           "10.8.0.0/24",
		ListenPort:       51820,
		ServerPrivateKey: "test-private-key",
		ServerPublicKey:  "test-public-key",
		DNS:              "1.1.1.1",
		AllowedIPs:       "0.0.0.0/0, ::/0",
		Keepalive:        25,
		PSKRequired:      true,
		IsolatePeers:     true,
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if tenant.ServerPrivateKey != "test-private-key" {
		t.Fatalf("private key did not round-trip: %q", tenant.ServerPrivateKey)
	}

	got, err := s.GetTenantByName(ctx, "acme")
	if err != nil {
		t.Fatalf("GetTenantByName: %v", err)
	}
	if got.ID != tenant.ID || got.Subnet != "10.8.0.0/24" {
		t.Fatalf("GetTenantByName mismatch: %+v", got)
	}
}

func TestCreateTenantDuplicateNameIsFriendlyError(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	in := TenantInput{Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820,
		ServerPrivateKey: "k1", ServerPublicKey: "p1"}

	if _, err := s.CreateTenant(ctx, in); err != nil {
		t.Fatalf("first CreateTenant: %v", err)
	}
	in.ServerPrivateKey, in.ServerPublicKey = "k2", "p2"
	_, err := s.CreateTenant(ctx, in)
	if err == nil {
		t.Fatal("expected duplicate tenant name error")
	}
	if got := err.Error(); !strings.Contains(got, "acme") {
		t.Fatalf("expected error to name the conflicting tenant, got: %v", got)
	}
}

func TestCreatePeerDuplicateAddressIsFriendlyError(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant, err := s.CreateTenant(ctx, TenantInput{
		Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820,
		ServerPrivateKey: "k", ServerPublicKey: "p",
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	base := PeerInput{
		TenantID: tenant.ID, Address: "10.8.0.2",
		AllowedIPs: "0.0.0.0/0", Keepalive: 25,
	}
	a := base
	a.Name, a.PublicKey, a.PrivateKey = "alice", "pub-a", "priv-a"
	if _, err := s.CreatePeer(ctx, a); err != nil {
		t.Fatalf("CreatePeer(alice): %v", err)
	}

	b := base
	b.Name, b.PublicKey, b.PrivateKey = "bob", "pub-b", "priv-b" // same address as alice
	_, err = s.CreatePeer(ctx, b)
	if err == nil {
		t.Fatal("expected duplicate address error when bob reuses alice's IP")
	}
	if got := err.Error(); !strings.Contains(got, "10.8.0.2") {
		t.Fatalf("expected error to name the conflicting address, got: %v", got)
	}
}

func TestUsedAddressesFeedsIPAM(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant, err := s.CreateTenant(ctx, TenantInput{
		Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820,
		ServerPrivateKey: "k", ServerPublicKey: "p",
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if _, err := s.CreatePeer(ctx, PeerInput{
		TenantID: tenant.ID, Name: "alice", Address: "10.8.0.2",
		PublicKey: "pub-a", PrivateKey: "priv-a", AllowedIPs: "0.0.0.0/0", Keepalive: 25,
	}); err != nil {
		t.Fatalf("CreatePeer: %v", err)
	}

	peers, err := s.ListPeers(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("ListPeers: %v", err)
	}
	var used []net.IP
	for _, p := range peers {
		used = append(used, net.ParseIP(p.Address))
	}

	subnet, err := ipam.ParseSubnet(tenant.Subnet)
	if err != nil {
		t.Fatalf("ParseSubnet: %v", err)
	}
	next, err := ipam.Next(subnet, used)
	if err != nil {
		t.Fatalf("ipam.Next: %v", err)
	}
	if next.String() != "10.8.0.3" {
		t.Fatalf("ipam.Next = %s, want 10.8.0.3 (next after alice's .2)", next)
	}
}

func TestDeleteTenantCascadesPeers(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant, err := s.CreateTenant(ctx, TenantInput{
		Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820,
		ServerPrivateKey: "k", ServerPublicKey: "p",
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if _, err := s.CreatePeer(ctx, PeerInput{
		TenantID: tenant.ID, Name: "alice", Address: "10.8.0.2",
		PublicKey: "pub-a", PrivateKey: "priv-a", AllowedIPs: "0.0.0.0/0", Keepalive: 25,
	}); err != nil {
		t.Fatalf("CreatePeer: %v", err)
	}

	if err := s.DeleteTenant(ctx, tenant.ID); err != nil {
		t.Fatalf("DeleteTenant: %v", err)
	}
	peers, err := s.ListPeers(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("ListPeers after delete: %v", err)
	}
	if len(peers) != 0 {
		t.Fatalf("expected peers to cascade-delete with tenant, got %d left", len(peers))
	}
}

// oldSchema is the tenants/peers schema exactly as it existed before
// isolation_exceptions and enabled were added — used to reproduce, and
// guard against regressing, a real bug: opening a database created by an
// earlier version of this program with the new code crash-looped the
// daemon with "no such column: isolation_exceptions" on every query,
// because CREATE TABLE IF NOT EXISTS is a no-op against a table that
// already exists, so the new columns in `schema` never actually reached
// an existing database — only Open's migrations do that.
const oldSchema = `
CREATE TABLE tenants (
	id                  INTEGER PRIMARY KEY AUTOINCREMENT,
	name                TEXT NOT NULL UNIQUE,
	subnet              TEXT NOT NULL,
	listen_port         INTEGER NOT NULL,
	server_private_key  BLOB NOT NULL,
	server_public_key   TEXT NOT NULL,
	dns                 TEXT NOT NULL DEFAULT '',
	allowed_ips         TEXT NOT NULL DEFAULT '0.0.0.0/0, ::/0',
	keepalive           INTEGER NOT NULL DEFAULT 25,
	psk_required        INTEGER NOT NULL DEFAULT 1,
	isolate_peers       INTEGER NOT NULL DEFAULT 1,
	created_at          TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE peers (
	id              INTEGER PRIMARY KEY AUTOINCREMENT,
	tenant_id       INTEGER NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
	name            TEXT NOT NULL,
	address         TEXT NOT NULL,
	public_key      TEXT NOT NULL,
	private_key     BLOB NOT NULL,
	preshared_key   BLOB,
	allowed_ips     TEXT NOT NULL,
	dns             TEXT NOT NULL DEFAULT '',
	keepalive       INTEGER NOT NULL DEFAULT 25,
	created_at      TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
	UNIQUE(tenant_id, address),
	UNIQUE(tenant_id, name),
	UNIQUE(tenant_id, public_key)
);
`

func TestOpenMigratesAPreExistingDatabaseMissingNewColumns(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.sqlite")
	var key [cryptutil.KeySize]byte
	sealer := cryptutil.NewSealer(key)

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatalf("sql.Open: %v", err)
	}
	if _, err := raw.Exec(oldSchema); err != nil {
		t.Fatalf("applying old schema: %v", err)
	}
	// A tenant created under the old schema, before Enabled existed — its
	// private key must be properly sealed, exactly as CreateTenant would
	// have stored it, so the migrated row round-trips like a real one.
	sealedKey, err := sealer.SealString("k")
	if err != nil {
		t.Fatalf("sealing test private key: %v", err)
	}
	if _, err := raw.Exec(`INSERT INTO tenants (name, subnet, listen_port, server_private_key, server_public_key)
		VALUES ('legacy', '10.9.0.0/24', 51820, ?, 'p')`, sealedKey); err != nil {
		t.Fatalf("inserting legacy tenant: %v", err)
	}
	if err := raw.Close(); err != nil {
		t.Fatalf("closing raw db: %v", err)
	}

	s, err := Open(path, sealer)
	if err != nil {
		t.Fatalf("Open on a pre-migration database: %v", err)
	}
	defer s.Close()

	ctx := context.Background()
	legacy, err := s.GetTenantByName(ctx, "legacy")
	if err != nil {
		t.Fatalf("reading a tenant that predates the enabled column: %v", err)
	}
	if !legacy.Enabled {
		t.Fatal("a pre-existing tenant should default to enabled after migration")
	}
	if legacy.IsolationExceptions != "" {
		t.Fatalf("expected empty isolation_exceptions default, got %q", legacy.IsolationExceptions)
	}

	// New functionality must work against the migrated database too.
	if err := s.SetTenantEnabled(ctx, legacy.ID, false); err != nil {
		t.Fatalf("SetTenantEnabled after migration: %v", err)
	}
	if _, err := s.CreatePeer(ctx, PeerInput{
		TenantID: legacy.ID, Name: "alice", Address: "10.9.0.2",
		PublicKey: "pub", PrivateKey: "priv", AllowedIPs: "0.0.0.0/0", Keepalive: 25,
	}); err != nil {
		t.Fatalf("CreatePeer after migration: %v", err)
	}
}

// TestOpenMigrationIsIdempotent guards the other direction: opening a
// brand-new database (where CREATE TABLE already includes every column)
// must not fail just because the migration ALTER TABLE statements then
// find those columns already present.
func TestOpenMigrationIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fresh.sqlite")
	var key [cryptutil.KeySize]byte
	sealer := cryptutil.NewSealer(key)

	if _, err := Open(path, sealer); err != nil {
		t.Fatalf("first Open: %v", err)
	}
	// Re-opening (simulating a process restart against the same file) must
	// also succeed, even though every migration is now a "duplicate
	// column" no-op.
	s2, err := Open(path, sealer)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	s2.Close()
}

func TestNewTenantsAndPeersStartEnabled(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant, err := s.CreateTenant(ctx, TenantInput{
		Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820,
		ServerPrivateKey: "k", ServerPublicKey: "p",
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if !tenant.Enabled {
		t.Fatal("a newly created tenant must start enabled")
	}
	peer, err := s.CreatePeer(ctx, PeerInput{
		TenantID: tenant.ID, Name: "alice", Address: "10.8.0.2",
		PublicKey: "pub-a", PrivateKey: "priv-a", AllowedIPs: "0.0.0.0/0", Keepalive: 25,
	})
	if err != nil {
		t.Fatalf("CreatePeer: %v", err)
	}
	if !peer.Enabled {
		t.Fatal("a newly created peer must start enabled")
	}
}

func TestSetTenantEnabledPersists(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant, err := s.CreateTenant(ctx, TenantInput{
		Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820,
		ServerPrivateKey: "k", ServerPublicKey: "p",
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}

	if err := s.SetTenantEnabled(ctx, tenant.ID, false); err != nil {
		t.Fatalf("SetTenantEnabled(false): %v", err)
	}
	got, err := s.GetTenant(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.Enabled {
		t.Fatal("expected tenant to be disabled after SetTenantEnabled(false)")
	}

	if err := s.SetTenantEnabled(ctx, tenant.ID, true); err != nil {
		t.Fatalf("SetTenantEnabled(true): %v", err)
	}
	got, err = s.GetTenant(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if !got.Enabled {
		t.Fatal("expected tenant to be re-enabled after SetTenantEnabled(true)")
	}
}

func TestSetTenantEnabledUnknownTenantReturnsNotFound(t *testing.T) {
	s := newTestStore(t)
	if err := s.SetTenantEnabled(context.Background(), 999, false); err != ErrNotFound {
		t.Fatalf("SetTenantEnabled on unknown id = %v, want ErrNotFound", err)
	}
}

func TestSetPeerEnabledPersists(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant, err := s.CreateTenant(ctx, TenantInput{
		Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820,
		ServerPrivateKey: "k", ServerPublicKey: "p",
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	peer, err := s.CreatePeer(ctx, PeerInput{
		TenantID: tenant.ID, Name: "alice", Address: "10.8.0.2",
		PublicKey: "pub-a", PrivateKey: "priv-a", AllowedIPs: "0.0.0.0/0", Keepalive: 25,
	})
	if err != nil {
		t.Fatalf("CreatePeer: %v", err)
	}

	if err := s.SetPeerEnabled(ctx, peer.ID, false); err != nil {
		t.Fatalf("SetPeerEnabled(false): %v", err)
	}
	got, err := s.GetPeer(ctx, peer.ID)
	if err != nil {
		t.Fatalf("GetPeer: %v", err)
	}
	if got.Enabled {
		t.Fatal("expected peer to be disabled after SetPeerEnabled(false)")
	}
	// Disabling must never touch the peer's keys — re-enabling should give
	// back the identical tunnel, not a regenerated one.
	if got.PrivateKey != "priv-a" || got.PublicKey != "pub-a" {
		t.Fatalf("disabling a peer must not change its keys, got private=%q public=%q", got.PrivateKey, got.PublicKey)
	}
}

func TestSetTenantIsolationExceptionsPersists(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()
	tenant, err := s.CreateTenant(ctx, TenantInput{
		Name: "acme", Subnet: "10.8.0.0/24", ListenPort: 51820,
		ServerPrivateKey: "k", ServerPublicKey: "p", IsolatePeers: true,
	})
	if err != nil {
		t.Fatalf("CreateTenant: %v", err)
	}
	if tenant.IsolationExceptions != "" {
		t.Fatalf("expected no exceptions by default, got %q", tenant.IsolationExceptions)
	}

	if err := s.SetTenantIsolationExceptions(ctx, tenant.ID, "10.8.0.5, 10.8.0.6"); err != nil {
		t.Fatalf("SetTenantIsolationExceptions: %v", err)
	}
	got, err := s.GetTenant(ctx, tenant.ID)
	if err != nil {
		t.Fatalf("GetTenant: %v", err)
	}
	if got.IsolationExceptions != "10.8.0.5, 10.8.0.6" {
		t.Fatalf("IsolationExceptions = %q, want %q", got.IsolationExceptions, "10.8.0.5, 10.8.0.6")
	}
}
