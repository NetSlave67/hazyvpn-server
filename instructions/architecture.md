# HazyVPN Server — Architecture & Build Rules

This document is the working spec for building HazyVPN Server. It expands the
raw requirements in `../instructions.md` into concrete technical decisions, so
the implementation stays consistent across sessions. Treat this as the source
of truth for "why it's built this way" — update it whenever a decision changes.

## What this is

A multi-tenant WireGuard server manager with a TUI, deployed as a Docker
container. One admin (you) runs the TUI on the server (or via `docker exec`)
to create tenants, add/remove road-warrior peers, and hand out configs —
without ever hand-editing `wg0.conf` or juggling overlapping subnets.

Sibling project: [NetSlave67/hazyvpn](https://github.com/NetSlave67/hazyvpn) —
the client-side TUI this is designed to pair with. Same visual language, same
"narrow privilege, validate everything" philosophy.

## Core design decisions

### 1. Language & TUI stack — matches the client exactly
Go, with:
- `charm.land/bubbletea/v2` — TUI runtime
- `charm.land/bubbles/v2` — list/input/viewport components
- `charm.land/lipgloss/v2` — styling, ANSI semantic colors (not hardcoded
  hex), rounded-border panels, same layout rhythm as the client's dashboard.
- `charm.land/log/v2` — structured logging to journal + state dir, same as
  client (`~/.local/state/hazyvpn/...` pattern, adapted to
  `/var/lib/hazyvpn-server/`).

Reuse the client's `theme.go`/`styles.go` pattern: semantic color vars
(`green`/`red`/`yellow`/`accent`/`textCol`/`dimCol`/`borderCol`/`base`) set
once from ANSI codes, so the terminal's theme drives the palette.

### 2. Multi-tenancy — Linux network namespaces, not just subnets
Each tenant gets its own network namespace (`ip netns add hazy-<tenant>`), its
own `wgN` interface inside that namespace, and its own veth pair into the
host for NAT/egress. Namespaces give us for free:
- Fully independent routing tables → two tenants can both use `10.0.0.0/24`
  with zero collision.
- Independent netfilter (nftables) state per namespace → tenant firewall
  rules can't leak into or be affected by another tenant.
- A hard blast-radius boundary: a compromised peer in tenant A's namespace
  cannot see tenant B's interfaces at all (not just "firewalled off").

This is the one piece of the system that needs real root/`CAP_NET_ADMIN` +
`CAP_SYS_ADMIN` (for the netns mount). It's isolated behind an
`internal/netns` package with a narrow interface (`Create`, `Destroy`,
`AttachWG`, `ApplyFirewall`) — everything above it works against that
interface, not raw syscalls, so it can be unit-tested with a fake.

### 3. IP address management (IPAM) — automatic, conflict-free by construction
- Each tenant has one subnet (user-settable at tenant creation, default
  suggestion e.g. `10.<n>.0.0/24`, editable).
- Adding a peer scans the tenant's WireGuard interface config (not the whole
  host) for IPs already in use and offers the next free host address —
  never requires the operator to type an IP.
- Because scanning is scoped to the tenant's own namespace/interface,
  duplicate-IP mistakes become structurally impossible across tenants, and
  within a tenant they're caught before the peer is ever written to disk.
- Manual IP entry is still allowed (operator override), but it's validated
  against the tenant's subnet and existing peers before accepting — clear
  error, not a silent overwrite.

### 4. Firewall — nftables, one ruleset per tenant namespace
Default-deny forward, explicit allow for: tenant subnet → internet (NAT via
host), optionally tenant subnet → specific allowed destinations/ports. Peer
isolation (can a road-warrior reach other road-warriors in the same tenant)
is a per-tenant toggle, default **on** (peers isolated from each other —
typical road-warrior setup), since WireGuard's `AllowedIPs` alone doesn't
stop peer-to-peer traffic at the server.

### 5. Storage
`modernc.org/sqlite` (pure Go, no cgo) at `/var/lib/hazyvpn-server/db.sqlite`.
Schema: `tenants` (id, name, subnet, dns, keepalive default, psk-required
flag, created_at), `peers` (id, tenant_id, name, public_key, preshared_key,
allowed_ips, address, created_at). Private keys for peers are generated
once, shown/exported once, and encrypted at rest with a server-local key
(file-mode-600, not committed, generated on first run) — same spirit as the
client stripping keys before display, inverted (server must hold them to
regenerate configs, but never logs them).

### 6. Config generation — sane defaults, fully overridable
Per-tenant defaults (editable at creation, applied unless overridden per
peer): `AllowedIPs` (default `0.0.0.0/0, ::/0` for full tunnel, or
tenant-subnet-only for split tunnel), `DNS`, `PersistentKeepalive` (default
`25`), preshared key (default **on**). Every field can be overridden per
peer at add-time.

### 7. QR codes
`github.com/skip2/go-qrcode` for on-demand QR generation: rendered as PNG
(for email/export) and as terminal ASCII (via the same library's string
output) for in-TUI display. Generated on demand or via an "always generate"
per-tenant toggle — never stored unless exported.

### 8. Import / export
- **Export**: single peer config (`.conf`), or a full tenant/all-tenants
  backup (tarball of configs + a redacted JSON manifest) to a path the
  operator chooses.
- **Import**: accept an existing WireGuard peer or full interface config;
  validate it doesn't collide with existing IPs/keys in the target tenant
  before writing.

### 9. Delivery — download, clipboard, email
- **Download**: write the rendered `.conf` (and QR PNG if requested) to a
  path the operator picks in the TUI.
- **Clipboard**: `github.com/atotto/clipboard` (same lib the client uses) —
  works when the TUI runs on a machine with clipboard access (local console
  or forwarded session); fails gracefully with a clear message over SSH
  without one, never a crash.
- **Email**: `github.com/wneessen/go-mail`, SMTP creds from an env-based
  config (`/etc/hazyvpn-server/config.yaml` + env override), sends the
  `.conf` and QR PNG as attachments. Credentials never logged.

### 10. Deployment — Docker only, nothing installed on the host beyond Docker
Single container, `docker-compose.yml` for the one-command path:
- Capabilities: `NET_ADMIN`, `NET_RAW`, `SYS_ADMIN` (netns mount), device
  `/dev/net/tun`, `sysctl net.ipv4.ip_forward=1` (and v6 equivalent).
- Relies on the **host kernel's** in-tree WireGuard module (default on
  effectively every current Linux kernel ≥5.6) — containers share the host
  kernel, so no userspace fallback is bundled initially. If you're on an
  older kernel without it, say so and we'll add a `wireguard-go` fallback.
- Persistent volumes: `/var/lib/hazyvpn-server` (db + keys), `/etc/hazyvpn-server`
  (config).
- The TUI is the container's entrypoint-adjacent admin tool, run via
  `docker exec -it hazyvpn-server hazyvpn-server`.

### 11. Error handling philosophy
Validate at the boundary (operator input, imported configs), trust internal
state otherwise. Every destructive action (delete tenant, delete peer,
overwrite on import) requires an explicit confirm step in the TUI. IP/key
collisions produce a specific, actionable message (which peer/tenant holds
the conflicting value) — never a generic "failed".

## Build order (status)

1. [x] Project scaffold (`go.mod`, directory layout, Makefile mirroring client's).
2. [x] `internal/ipam` — pure logic, unit-tested, no root needed.
3. [x] `internal/store` — SQLite schema + queries, with keys encrypted at
   rest via `internal/cryptutil`.
4. [x] `internal/wgconf` — keypair generation, config rendering/parsing for
   server and peer configs.
5. [x] `internal/qrcode`, `internal/mail` — self-contained, unit-testable.
6. [x] `internal/netns` — privileged orchestration (netns, veth, nftables,
   wg interface lifecycle, host port-forwarding). Exercised in unit tests
   against a fake command runner; real netns/root behavior only provable
   under Docker.
7. [x] `internal/app` — the Service layer tying all of the above together
   (tenant/peer CRUD, IP suggestion, import/export, email, and startup
   reconciliation). This is where cross-package correctness (duplicate-IP
   rejection, rollback-on-failure) is actually tested.
8. [x] `cmd/hazyvpn-server` — Bubble Tea TUI wired to `internal/app`, split
   into a `daemon` subcommand (the container's long-running process —
   reconciles tenants, then idles) and the default TUI invocation (run via
   `docker exec`), so quitting the TUI never takes tenants' namespaces down.
9. [x] `Dockerfile` + `docker-compose.yml`.
10. [x] `README.md` (install/deploy/usage, mirroring client's README structure).
11. [ ] Push to `github.com/NetSlave67/hazyvpn-server` — blocked on
    `gh auth login` (no GitHub credentials available in the build
    environment); repo is committed locally and ready to push.
12. [ ] First real-world validation on an actual Docker host/VM: create a
    tenant, confirm `ip netns`/`wg`/`nft` state, add a peer, and connect a
    real WireGuard client. Everything up to the namespace/firewall syscalls
    themselves is unit-tested, but nothing has exercised real root/netns
    behavior yet — do this before relying on it for anything real.

## Non-goals (for now)

No web UI, no multi-admin auth/RBAC, no clustering/HA, no non-Linux support.
These can be reconsidered once the single-node TUI tool is solid.
