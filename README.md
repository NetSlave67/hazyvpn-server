# HazyVPN Server

A multi-tenant WireGuard server manager with a fast, keyboard-driven TUI —
create isolated tenants, add and remove road-warrior peers, and hand out
configs (as text, QR code, download, or email) without ever hand-editing
`wg0.conf`.

```
HazyVPN Server  2 tenant(s)

╭─ Tenants ──────────────────────────╮  ╭─ Peers — acme ─────────────────────╮
│                                     │  │                                     │
│ › acme · 10.8.0.0/24 · :51820       │  │ › alice · 10.8.0.2 · aBcD12eFgH…   │
│   contoso · 10.9.0.0/24 · :51821    │  │   bob   · 10.8.0.3 · zYxW98vUtS…   │
│                                     │  │                                     │
╰─────────────────────────────────────╯  ╰─────────────────────────────────────╯

n new tenant • a add peer • x delete • ? help • q quit
```

Each tenant gets its own Linux network namespace, its own WireGuard
interface, and its own firewall rules — so two tenants can both use
`10.0.0.0/24` with zero collision, and a compromised peer in one tenant
can't see another tenant's interfaces at all.

Sibling project: [NetSlave67/hazyvpn](https://github.com/NetSlave67/hazyvpn)
— the client-side TUI this pairs with. Same visual language, same "narrow
privilege, validate everything" philosophy.

## Features

- **True multi-tenancy** via Linux network namespaces — not just separate
  subnets. Overlapping subnets across tenants are safe by construction.
- **Automatic IP assignment.** Adding a peer scans the tenant's existing
  peers and suggests the next free address — never type an IP by hand.
  Manual overrides are validated and rejected with a specific error if
  they collide (no more "wait, who else is using .2?").
- **Sane, overridable defaults.** Subnet, listen port, DNS, AllowedIPs,
  keepalive, and preshared-key usage all have sensible defaults you can
  change per tenant or per peer.
- **QR codes and config files on demand** — view, download, or copy to
  clipboard, generated fresh each time rather than stored.
- **Per-tenant firewall.** Peer isolation (block road-warriors from
  reaching each other) is a per-tenant toggle, backed by nftables.
- **Import / export.** Restore a full tenant (settings + every peer's
  keys) from a JSON backup, or import a single external peer `.conf` —
  configs carrying `PreUp`/`PostUp`/`PreDown`/`PostDown` hooks are refused.
- **Email delivery.** Send a peer their config and QR code directly via
  SMTP.
- **Survives restarts.** Tenant/peer state lives in SQLite on a volume;
  namespaces are reconciled (recreated if needed) every time the server
  starts, independent of whether the TUI is open.

## Deploying

Requires Docker (or a VM with Docker) — nothing else is installed on the
host. The host's kernel needs in-tree WireGuard support, which is the
default on effectively every Linux kernel ≥5.6.

```sh
git clone https://github.com/NetSlave67/hazyvpn-server.git
cd hazyvpn-server
cp config.example.yaml config.yaml
$EDITOR config.yaml   # at minimum, set public_host to your server's address
docker compose up -d --build
```

This starts the container's long-running process — a small daemon that
reconciles every tenant's namespace against the database and then idles.
It is **not** the TUI, so stopping the TUI never takes your tenants down.

To manage tenants and peers, run the TUI inside the running container:

```sh
docker exec -it hazyvpn-server hazyvpn-server
```

### Ports

`docker-compose.yml` publishes UDP `51820-51920` by default (100 tenants'
worth of listen ports — each tenant needs one, unique, publicly-reachable
UDP port). Widen the range in `docker-compose.yml` if you expect more
tenants than that, or if you want to free-choose listen ports outside it.

### Configuration

See `config.example.yaml`. Every field can also be set via environment
variable (`HAZYVPN_DATA_DIR`, `HAZYVPN_PUBLIC_HOST`, `HAZYVPN_EXPORT_DIR`,
`HAZYVPN_SMTP_HOST`, `HAZYVPN_SMTP_PORT`, `HAZYVPN_SMTP_USERNAME`,
`HAZYVPN_SMTP_PASSWORD`, `HAZYVPN_SMTP_FROM`), which take precedence over
the file — handy for keeping SMTP credentials out of `config.yaml`
entirely.

## Keybindings

| Key       | Action                              |
|-----------|--------------------------------------|
| `j`/`k`, `↑`/`↓` | move                          |
| `tab`     | switch between the tenant/peer panes |
| `n`       | new tenant                           |
| `a`       | add peer to the selected tenant      |
| `x`       | delete the selected tenant/peer      |
| `v`       | view the selected peer's config      |
| `g`       | show the selected peer's QR code     |
| `c`       | copy the selected peer's config to the clipboard |
| `d`       | export/download (peer config+QR, or a full tenant backup) |
| `i`       | import (a peer `.conf`, or a tenant backup) |
| `e`       | email the selected peer's config     |
| `?`       | help                                 |
| `q`       | quit                                 |
| `ctrl+c`  | force quit                           |

## How multi-tenancy works

Each tenant is: a network namespace (`ip netns`), a `wg0` interface inside
it, a veth link back to the host for NAT/egress, and its own nftables
ruleset. Because namespaces have fully independent routing tables and
netfilter state:

- Two tenants can both use the same subnet with zero chance of collision.
- A tenant's firewall rules (peer isolation, default-deny) can't leak into
  or be affected by another tenant's.
- The container forwards each tenant's published UDP port into that
  tenant's namespace via a single, additive DNAT table in its own top-level
  namespace, picking up right where Docker's own port-publishing leaves
  off — it never touches or overrides Docker's own iptables/nftables
  management.

See `instructions/architecture.md` for the full design rationale.

## Development

```sh
go build ./...              # build
go vet ./...                # vet
go test ./...                # unit tests (no root required — the
                              #   namespace/firewall orchestration layer is
                              #   tested against a fake command runner)
go build -o hazyvpn-server ./cmd/hazyvpn-server
```

Exercising the namespace/WireGuard/firewall orchestration for real needs
root and a Linux kernel with WireGuard support — that's what
`docker compose up` is for.

Built with [Bubble Tea](https://charm.land) (v2), Bubbles, and Lip Gloss —
the same stack as the client-side [hazyvpn](https://github.com/NetSlave67/hazyvpn) TUI.

## Credits

Design language and safety philosophy carried over from
[NetSlave67/hazyvpn](https://github.com/NetSlave67/hazyvpn), itself a
distro-agnostic derivative of [omarchy-vpn](https://github.com/limehawk/omarchy-vpn)
by Limehawk (MIT license).
