// Package ipam allocates and validates peer addresses within a tenant's
// WireGuard subnet. It never touches the network itself — callers pass in
// the set of addresses already in use (typically read back from a tenant's
// peer records) and get a conflict-free suggestion or a specific error.
package ipam

import (
	"fmt"
	"math/big"
	"net"
)

// ErrSubnetExhausted is returned when a subnet has no free host addresses left.
var ErrSubnetExhausted = fmt.Errorf("ipam: subnet has no free addresses")

// ParseSubnet parses a CIDR string (e.g. "10.8.0.0/24") into a *net.IPNet,
// normalizing it to its network address.
func ParseSubnet(cidr string) (*net.IPNet, error) {
	ip, network, err := net.ParseCIDR(cidr)
	if err != nil {
		return nil, fmt.Errorf("ipam: invalid subnet %q: %w", cidr, err)
	}
	if ip.Equal(network.IP) == false {
		return nil, fmt.Errorf("ipam: %q is not a network address, did you mean %s?", cidr, network.String())
	}
	return network, nil
}

// reserved returns the set of addresses within subnet that should never be
// handed out to a peer: the network address itself, the gateway address
// (first usable host — the server's own tunnel address), and for IPv4 the
// broadcast address.
func reserved(subnet *net.IPNet) map[string]bool {
	r := map[string]bool{subnet.IP.String(): true}
	if gw := GatewayAddress(subnet); gw != nil {
		r[gw.String()] = true
	}
	if bcast := broadcastAddress(subnet); bcast != nil {
		r[bcast.String()] = true
	}
	return r
}

// GatewayAddress returns the conventional first usable host address in the
// subnet (network address + 1) — the address the tenant's server-side
// WireGuard interface should bind to.
func GatewayAddress(subnet *net.IPNet) net.IP {
	return offsetIP(subnet.IP, 1)
}

// broadcastAddress returns the IPv4 broadcast address for subnet, or nil for
// IPv6 (which has no broadcast concept).
func broadcastAddress(subnet *net.IPNet) net.IP {
	ip4 := subnet.IP.To4()
	if ip4 == nil {
		return nil
	}
	mask := subnet.Mask
	bcast := make(net.IP, len(ip4))
	for i := range ip4 {
		bcast[i] = ip4[i] | ^mask[i]
	}
	return bcast
}

// offsetIP returns base + n as a net.IP of the same length/family as base.
func offsetIP(base net.IP, n int64) net.IP {
	bi := new(big.Int).SetBytes(base)
	bi.Add(bi, big.NewInt(n))
	out := bi.Bytes()
	full := make(net.IP, len(base))
	copy(full[len(full)-len(out):], out)
	return full
}

// Contains reports whether subnet contains ip.
func Contains(subnet *net.IPNet, ip net.IP) bool {
	return subnet.Contains(ip)
}

// Validate checks that addr is a usable, conflict-free host address for the
// given subnet and set of addresses already in use. It returns a specific
// error describing exactly what's wrong (out of range vs. collision) rather
// than a generic failure.
func Validate(subnet *net.IPNet, addr net.IP, used []net.IP) error {
	if addr == nil {
		return fmt.Errorf("ipam: empty address")
	}
	if !subnet.Contains(addr) {
		return fmt.Errorf("ipam: %s is not within subnet %s", addr, subnet)
	}
	if reserved(subnet)[addr.String()] {
		return fmt.Errorf("ipam: %s is reserved (network/gateway/broadcast address)", addr)
	}
	for _, u := range used {
		if u.Equal(addr) {
			return fmt.Errorf("ipam: %s is already assigned to another peer", addr)
		}
	}
	return nil
}

// Next scans subnet in order starting after the gateway address and returns
// the first host address not in used and not reserved. This is what the TUI
// calls when adding a peer, so the operator never has to type an IP.
func Next(subnet *net.IPNet, used []net.IP) (net.IP, error) {
	usedSet := make(map[string]bool, len(used))
	for _, u := range used {
		usedSet[u.String()] = true
	}
	res := reserved(subnet)

	ones, bits := subnet.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 0 {
		return nil, ErrSubnetExhausted
	}
	// Total addresses in the subnet, minus network address itself.
	total := new(big.Int).Lsh(big.NewInt(1), uint(hostBits))

	for i := int64(1); big.NewInt(i).Cmp(total) < 0; i++ {
		candidate := offsetIP(subnet.IP, i)
		key := candidate.String()
		if res[key] || usedSet[key] {
			continue
		}
		return candidate, nil
	}
	return nil, ErrSubnetExhausted
}

// Capacity returns the number of usable host addresses in subnet (excluding
// network, gateway, and — for IPv4 — broadcast).
func Capacity(subnet *net.IPNet) int64 {
	ones, bits := subnet.Mask.Size()
	hostBits := bits - ones
	if hostBits <= 0 {
		return 0
	}
	total := int64(1) << uint(hostBits)
	reservedCount := int64(len(reserved(subnet)))
	if total-reservedCount < 0 {
		return 0
	}
	return total - reservedCount
}
