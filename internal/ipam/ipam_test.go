package ipam

import (
	"net"
	"testing"
)

func mustSubnet(t *testing.T, cidr string) *net.IPNet {
	t.Helper()
	n, err := ParseSubnet(cidr)
	if err != nil {
		t.Fatalf("ParseSubnet(%q): %v", cidr, err)
	}
	return n
}

func TestParseSubnetRejectsHostAddress(t *testing.T) {
	if _, err := ParseSubnet("10.8.0.5/24"); err == nil {
		t.Fatal("expected error for non-network address")
	}
}

func TestGatewayAddress(t *testing.T) {
	n := mustSubnet(t, "10.8.0.0/24")
	if got := GatewayAddress(n); got.String() != "10.8.0.1" {
		t.Fatalf("GatewayAddress = %s, want 10.8.0.1", got)
	}
}

func TestNextSkipsReservedAndUsed(t *testing.T) {
	n := mustSubnet(t, "10.8.0.0/30") // usable hosts: .1 (gw), .2
	used := []net.IP{net.ParseIP("10.8.0.1")}
	got, err := Next(n, used)
	if err != nil {
		t.Fatalf("Next: %v", err)
	}
	if got.String() != "10.8.0.2" {
		t.Fatalf("Next = %s, want 10.8.0.2", got)
	}
}

func TestNextExhausted(t *testing.T) {
	n := mustSubnet(t, "10.8.0.0/30")
	used := []net.IP{net.ParseIP("10.8.0.1"), net.ParseIP("10.8.0.2")}
	if _, err := Next(n, used); err != ErrSubnetExhausted {
		t.Fatalf("Next = %v, want ErrSubnetExhausted", err)
	}
}

func TestValidateCatchesDuplicateIP(t *testing.T) {
	n := mustSubnet(t, "10.8.0.0/24")
	used := []net.IP{net.ParseIP("10.8.0.5")}
	err := Validate(n, net.ParseIP("10.8.0.5"), used)
	if err == nil {
		t.Fatal("expected duplicate IP error")
	}
}

func TestValidateCatchesOutOfRange(t *testing.T) {
	n := mustSubnet(t, "10.8.0.0/24")
	err := Validate(n, net.ParseIP("10.9.0.5"), nil)
	if err == nil {
		t.Fatal("expected out-of-range error")
	}
}

func TestValidateRejectsReservedAddresses(t *testing.T) {
	n := mustSubnet(t, "10.8.0.0/24")
	for _, addr := range []string{"10.8.0.0", "10.8.0.1", "10.8.0.255"} {
		if err := Validate(n, net.ParseIP(addr), nil); err == nil {
			t.Fatalf("expected %s to be rejected as reserved", addr)
		}
	}
}

func TestCapacitySlash24(t *testing.T) {
	n := mustSubnet(t, "10.8.0.0/24")
	// 254 host addresses minus network(.0) already excluded from host range,
	// minus gateway(.1) and broadcast(.255) => 253 usable for peers.
	if got := Capacity(n); got != 253 {
		t.Fatalf("Capacity = %d, want 253", got)
	}
}

func TestOverlappingSubnetsAreIndependent(t *testing.T) {
	// Two tenants both using 10.0.0.0/24 must not conflict with each other —
	// IPAM only ever looks at the "used" list the caller passes in, which is
	// scoped per tenant/namespace, so identical subnets never collide here.
	a := mustSubnet(t, "10.0.0.0/24")
	b := mustSubnet(t, "10.0.0.0/24")
	usedA := []net.IP{net.ParseIP("10.0.0.2")}
	usedB := []net.IP{net.ParseIP("10.0.0.2"), net.ParseIP("10.0.0.3")}

	gotA, err := Next(a, usedA)
	if err != nil {
		t.Fatalf("Next(a): %v", err)
	}
	gotB, err := Next(b, usedB)
	if err != nil {
		t.Fatalf("Next(b): %v", err)
	}
	if gotA.String() != "10.0.0.3" {
		t.Fatalf("Next(a) = %s, want 10.0.0.3", gotA)
	}
	if gotB.String() != "10.0.0.4" {
		t.Fatalf("Next(b) = %s, want 10.0.0.4", gotB)
	}
}
