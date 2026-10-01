// Package netns orchestrates one Linux network namespace per tenant: its
// veth link to the host, its WireGuard interface, and its nftables
// ruleset. This is the one part of HazyVPN Server that needs real
// root/CAP_NET_ADMIN/CAP_SYS_ADMIN — everything here goes through the
// Runner interface so the orchestration logic itself can be unit-tested
// with a fake, without touching the real network stack.
package netns

import (
	"fmt"
	"net"
	"os"
	"strings"
)

// Manager creates, tears down, and configures tenant network namespaces.
type Manager struct {
	run Runner
}

// NewManager returns a Manager backed by real system commands.
func NewManager() *Manager {
	return &Manager{run: execRunner{}}
}

// newManagerWithRunner is used by tests to inject a fake Runner.
func newManagerWithRunner(r Runner) *Manager {
	return &Manager{run: r}
}

// EnsureHostForwarding turns on IPv4 forwarding on the host. It's
// idempotent and only needs to run once at server startup, not per tenant.
func (m *Manager) EnsureHostForwarding() error {
	_, err := m.run.Run("sysctl", "-w", "net.ipv4.ip_forward=1")
	return err
}

// Create brings up a tenant's namespace: the namespace itself, a veth link
// to the host, and a wg0 interface bound to gatewayCIDR (the tenant's own
// first usable address, e.g. "10.8.0.1/24"). The interface's private key and
// listen port are applied afterward via SyncWireGuard. If any step fails,
// Create tears down everything it already made rather than leaving a
// half-built namespace behind.
func (m *Manager) Create(tenantID int64, gatewayCIDR string) (err error) {
	ns := Namespace(tenantID)
	hostVeth, err := HostVeth(tenantID)
	if err != nil {
		return err
	}
	hostLink, nsLink, prefix, err := LinkAddresses(tenantID)
	if err != nil {
		return err
	}

	defer func() {
		if err != nil {
			_ = m.Destroy(tenantID) // best-effort: don't leave a half-built namespace around
		}
	}()

	if _, err = m.run.Run("ip", "netns", "add", ns); err != nil {
		return fmt.Errorf("netns: creating namespace: %w", err)
	}
	if _, err = m.run.Run("ip", "link", "add", hostVeth, "type", "veth", "peer", "name", nsVeth); err != nil {
		return fmt.Errorf("netns: creating veth pair: %w", err)
	}
	if _, err = m.run.Run("ip", "link", "set", nsVeth, "netns", ns); err != nil {
		return fmt.Errorf("netns: moving veth into namespace: %w", err)
	}
	if _, err = m.run.Run("ip", "addr", "add", cidr(hostLink, prefix), "dev", hostVeth); err != nil {
		return fmt.Errorf("netns: addressing host veth: %w", err)
	}
	if _, err = m.run.Run("ip", "link", "set", hostVeth, "up"); err != nil {
		return fmt.Errorf("netns: bringing up host veth: %w", err)
	}

	nsExec := []string{"netns", "exec", ns}
	steps := [][]string{
		append(append([]string{}, nsExec...), "ip", "link", "set", "lo", "up"),
		append(append([]string{}, nsExec...), "ip", "addr", "add", cidr(nsLink, prefix), "dev", nsVeth),
		append(append([]string{}, nsExec...), "ip", "link", "set", nsVeth, "up"),
		append(append([]string{}, nsExec...), "ip", "route", "add", "default", "via", hostLink.String()),
		append(append([]string{}, nsExec...), "ip", "link", "add", WGInterface, "type", "wireguard"),
		append(append([]string{}, nsExec...), "ip", "addr", "add", gatewayCIDR, "dev", WGInterface),
		append(append([]string{}, nsExec...), "ip", "link", "set", WGInterface, "up"),
	}
	for _, args := range steps {
		if _, err = m.run.Run("ip", args...); err != nil {
			return fmt.Errorf("netns: %v: %w", args, err)
		}
	}
	return nil
}

// Exists reports whether a tenant's namespace is currently up. The server
// reconciles its database against live namespaces at every startup — a
// container restart loses all namespaces even though the database (on a
// volume) survives, so this is what tells Reconcile which tenants need to
// be recreated versus just have their config re-synced.
func (m *Manager) Exists(tenantID int64) (bool, error) {
	ns := Namespace(tenantID)
	_, err := m.run.Run("ip", "netns", "exec", ns, "true")
	if err == nil {
		return true, nil
	}
	if isNotExist(err) {
		return false, nil
	}
	return false, err
}

// Destroy removes a tenant's namespace and everything inside it (its veth
// end, wg0, routes). Deleting the namespace's veth end automatically
// destroys its host-side pair, but Destroy also makes a best-effort attempt
// to remove the host veth directly in case the namespace was never fully
// created, and ignores "doesn't exist" errors from either step.
func (m *Manager) Destroy(tenantID int64) error {
	ns := Namespace(tenantID)
	hostVeth, vethErr := HostVeth(tenantID)

	_, delErr := m.run.Run("ip", "netns", "del", ns)
	if delErr != nil && !isNotExist(delErr) {
		return fmt.Errorf("netns: deleting namespace %s: %w", ns, delErr)
	}
	if vethErr == nil {
		if _, err := m.run.Run("ip", "link", "del", hostVeth); err != nil && !isNotExist(err) {
			return fmt.Errorf("netns: removing leftover host veth %s: %w", hostVeth, err)
		}
	}
	return nil
}

// SyncWireGuard replaces the WireGuard interface/peer configuration inside
// a tenant's namespace with configText (as rendered by
// wgconf.RenderServerConfig), without flapping the interface.
func (m *Manager) SyncWireGuard(tenantID int64, configText string) error {
	ns := Namespace(tenantID)
	tmp, err := os.CreateTemp("", "hazyvpn-wg-*.conf")
	if err != nil {
		return fmt.Errorf("netns: writing temp config: %w", err)
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.WriteString(configText); err != nil {
		tmp.Close()
		return fmt.Errorf("netns: writing temp config: %w", err)
	}
	tmp.Close()

	if _, err := m.run.Run("ip", "netns", "exec", ns, "wg", "setconf", WGInterface, tmp.Name()); err != nil {
		return fmt.Errorf("netns: applying WireGuard config: %w", err)
	}
	return nil
}

// ApplyFirewall replaces the tenant namespace's nftables ruleset with the
// one described by spec.
func (m *Manager) ApplyFirewall(tenantID int64, spec FirewallSpec) error {
	ns := Namespace(tenantID)
	ruleset := Ruleset(spec)
	if _, err := m.run.RunStdin("ip", ruleset, "netns", "exec", ns, "nft", "-f", "-"); err != nil {
		return fmt.Errorf("netns: applying firewall rules: %w", err)
	}
	return nil
}

func cidr(ip net.IP, prefixLen int) string {
	return fmt.Sprintf("%s/%d", ip, prefixLen)
}

// isNotExist is a best-effort check for "that object is already gone" so
// Destroy can be called safely on a namespace that was never fully created.
func isNotExist(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "Cannot find device") ||
		strings.Contains(msg, "No such file or directory") ||
		strings.Contains(msg, "does not exist") ||
		strings.Contains(msg, "Cannot remove namespace file")
}
