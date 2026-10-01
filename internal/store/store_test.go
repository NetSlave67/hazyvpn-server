package store

import (
	"context"
	"net"
	"path/filepath"
	"strings"
	"testing"

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
