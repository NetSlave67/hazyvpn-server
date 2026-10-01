package netns

import "testing"

func TestNamespaceIsStablePerTenant(t *testing.T) {
	if Namespace(1) == Namespace(2) {
		t.Fatal("different tenants produced the same namespace name")
	}
	if Namespace(1) != Namespace(1) {
		t.Fatal("Namespace is not deterministic")
	}
}

func TestHostVethFitsIFNAMSIZ(t *testing.T) {
	name, err := HostVeth(42)
	if err != nil {
		t.Fatalf("HostVeth: %v", err)
	}
	if len(name) > 15 {
		t.Fatalf("HostVeth name %q exceeds 15 chars", name)
	}
}

func TestHostVethRejectsOversizedID(t *testing.T) {
	if _, err := HostVeth(99999999999); err == nil {
		t.Fatal("expected error for an id that produces a name over 15 chars")
	}
}

func TestLinkAddressesDistinctAndWithinSubnet(t *testing.T) {
	h1, n1, prefix, err := LinkAddresses(0)
	if err != nil {
		t.Fatalf("LinkAddresses(0): %v", err)
	}
	h2, n2, _, err := LinkAddresses(1)
	if err != nil {
		t.Fatalf("LinkAddresses(1): %v", err)
	}
	if prefix != 30 {
		t.Fatalf("prefix = %d, want 30", prefix)
	}
	if h1.Equal(h2) || n1.Equal(n2) || h1.Equal(n1) {
		t.Fatalf("expected four distinct addresses, got %s %s %s %s", h1, n1, h2, n2)
	}
	h1v4 := h1.To4()
	if h1v4[0] != 169 || h1v4[1] != 254 {
		t.Fatalf("host link address %s is not in 169.254.0.0/16", h1)
	}
}

func TestLinkAddressesRejectsOutOfRangeTenant(t *testing.T) {
	if _, _, _, err := LinkAddresses(maxTenantsForLinkAddressing); err == nil {
		t.Fatal("expected error for tenant id beyond addressing capacity")
	}
}
