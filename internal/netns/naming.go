package netns

import (
	"fmt"
	"net"
)

// System-level object names are derived purely from a tenant's numeric ID,
// never from its operator-chosen display name. That sidesteps an entire
// class of validation bugs (charset, length, IFNAMSIZ limits) — the operator
// can rename a tenant freely without touching a single kernel object.

const (
	// WGInterface is the WireGuard interface name inside every tenant
	// namespace. Namespaces isolate interface names from each other, so
	// every tenant can safely use the same one.
	WGInterface = "wg0"
	// nsVeth is the namespace-side end of the host<->namespace veth pair,
	// for the same reason always the same name across tenants.
	nsVeth = "veth0"
	// linkBase is the start of the RFC 3927 link-local range used for
	// point-to-point host<->namespace addressing. It's never routed beyond
	// the host and never seen by WireGuard peers.
	linkBase = "169.254.0.0"
	// LinkRangeCIDR is the full range linkBase addresses are drawn from.
	// Traffic leaving a tenant's namespace is already MASQUERADEd to an
	// address in this range (see Ruleset's postrouting chain) before it
	// reaches the container's own namespace — that address needs a second
	// MASQUERADE of its own before it can leave *that* namespace too (see
	// HostRuleset's postrouting chain), since it's link-local and Docker's
	// own NAT only covers its bridge subnet, not this one.
	LinkRangeCIDR = "169.254.0.0/16"
)

// maxTenantsForLinkAddressing is how many /30 point-to-point links fit in
// the /16 link-local range this package reserves for veth addressing.
const maxTenantsForLinkAddressing = 1 << 14 // 169.254.0.0/16 in /30s

// Namespace returns the network namespace name for a tenant.
func Namespace(tenantID int64) string {
	return fmt.Sprintf("hazy-t%d", tenantID)
}

// HostVeth returns the host-side veth interface name for a tenant. It must
// fit within Linux's 15-character IFNAMSIZ limit, which bounds how large
// tenantID can get — see maxTenantsForLinkAddressing for the practical cap.
func HostVeth(tenantID int64) (string, error) {
	name := fmt.Sprintf("hveth%d", tenantID)
	if len(name) > 15 {
		return "", fmt.Errorf("netns: tenant id %d produces a veth name longer than 15 characters", tenantID)
	}
	return name, nil
}

// LinkAddresses returns the host-side and namespace-side /30 point-to-point
// addresses used to route a tenant's traffic from its namespace to the host
// (and from there, out to the internet via NAT).
func LinkAddresses(tenantID int64) (host net.IP, ns net.IP, prefixLen int, err error) {
	if tenantID < 0 || tenantID >= maxTenantsForLinkAddressing {
		return nil, nil, 0, fmt.Errorf("netns: tenant id %d exceeds link-addressing capacity (%d tenants)", tenantID, maxTenantsForLinkAddressing)
	}
	base := net.ParseIP(linkBase).To4()
	offset := uint32(tenantID) * 4
	baseVal := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
	host = uint32ToIP(baseVal + offset + 1)
	ns = uint32ToIP(baseVal + offset + 2)
	return host, ns, 30, nil
}

func uint32ToIP(v uint32) net.IP {
	return net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
