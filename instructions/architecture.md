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
host). Peer isolation (can a road-warrior reach other road-warriors in the
same tenant) is a per-tenant toggle, default **on** (peers isolated from
each other — typical road-warrior setup), since WireGuard's `AllowedIPs`
alone doesn't stop peer-to-peer traffic at the server.

On top of that, each tenant has an ordered list of custom firewall rules
(`store.FirewallRule` / `internal/netns.FirewallRule`) — see "Custom
firewall rules" below for the full redesign that replaced the original
single-field "isolation exceptions" allow-list.

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
- Persistent volume: `/var/lib/hazyvpn-server` (db + keys). `/etc/hazyvpn-server`
  is deliberately **not** a Docker volume — it only ever holds a single
  operator-supplied, read-only `config.yaml` bind-mounted in by
  docker-compose.yml. Declaring it as a volume too (an earlier mistake)
  made Docker manage it as an anonymous volume, which raced with that file
  bind-mount on container recreation and intermittently mounted
  `config.yaml` as a directory instead of a file.
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
11. [x] Pushed to `github.com/NetSlave67/hazyvpn-server` (`main`).
12. [x] First real-world validation, on Martin's own machine via
    `docker compose up`. Found and fixed three real bugs the unit tests
    couldn't catch (none involve fake-able logic — all three only show up
    against a real kernel/Docker):
    - `wg setconf` (the plain wg(8) config parser, as opposed to
      wg-quick's extended format) rejected our rendered `Address` line
      outright ("Line unrecognized") and aborted every tenant creation.
      `ServerInterfaceConfig`/`RenderServerConfig` no longer emit it — the
      tenant's address is assigned separately via `ip addr add` in
      `netns.Manager.Create`, which was always correct.
    - That failure exposed a second bug: `bringUpTenant` created the
      namespace successfully before failing on the WireGuard sync step,
      and nothing tore it back down — `CreateTenant`'s rollback only
      deleted the DB row, leaving a live, fully-networked orphan
      namespace behind. Fixed with a defer in `bringUpTenant`.
    - The Dockerfile declared `/etc/hazyvpn-server` as a `VOLUME` even
      though it only ever holds a single bind-mounted `config.yaml` file —
      this made Docker manage it as an anonymous volume, which raced with
      the file bind-mount on container recreation and intermittently
      mounted `config.yaml` as a directory instead of a file. Removed
      from `VOLUME`; only `/var/lib/hazyvpn-server` is a real volume now.

    After all three fixes: tenant creation, peer creation, QR/config
    rendering, and the full host-port-forwarding chain (Docker's own
    published-port DNAT → the container's own `hazyvpn_host` DNAT table →
    the nested tenant namespace's `wg0`) were all confirmed working
    end-to-end against real `ip netns`/`wg`/`nft` state — see `wg show`
    and `nft list ruleset` output captured during that session for exact
    expected values.

    **Still open:** this was all tested from the same LAN as the host
    (`public_host` set to its LAN IP, e.g. `192.168.x.x`), not a real
    internet-facing client. The host runs `ufw` with
    `DEFAULT_FORWARD_POLICY="DROP"` — Docker's own rules usually take
    priority over ufw's for published-port forwarding, but this
    hasn't been confirmed with an actual external/cross-NAT connection
    attempt. If a real WireGuard client fails to complete a handshake
    once this is deployed for real (non-LAN) use, ufw's forward chain is
    the first thing to check (`sudo ufw route allow proto udp from any to
    any port <range>` or similar, or switching `DEFAULT_FORWARD_POLICY`
    to `ACCEPT`).
13. [x] Full feature + error-handling sweep, driven directly through a live
    TUI session against the real container (every form validation path,
    every confirm/cancel flow, both import types including the dangerous-
    hooks rejection, export, email, clipboard, help, and the two-tenants-
    sharing-a-subnet claim re-verified at the kernel level). Found and
    fixed three more real bugs:
    - nft rule accumulation: `nft -f -` re-feeding an already-existing
      `table { chain { ... } }` *appends* its rules rather than replacing
      them (rules are identified by handle, not content). Every tenant
      create and every daemon/TUI startup reconcile re-applies both
      `Ruleset` (per-tenant firewall) and `HostRuleset` (port forwarding),
      so rulesets were doubling on every restart — confirmed live. Both
      now open with `add table` + `flush table`.
    - That accumulation is what surfaced a second bug: restoring a backup
      under a new name, alongside its still-live original, silently reused
      the original's listen port — two tenants sharing a port is a *silent*
      failure (the DNAT table can only route it to one of them).
      `ImportTenantBackup` now validates listen-port uniqueness like
      `CreateTenant` always did, and the TUI gained a "New Listen Port"
      override field alongside the "New Name" one added earlier in this
      same pass (the name collision was always caught; nothing let you
      resolve it without hand-editing the backup JSON until now).
    - `startDelete()` gave zero feedback when nothing was selected, unlike
      every other action. Now consistent.

    Everything else held up under direct testing with no changes needed:
    every IPAM validation message (duplicate/out-of-subnet/reserved
    address), duplicate tenant name/listen port rejection, cascade-delete,
    clipboard-unavailable graceful failure, SMTP-not-configured graceful
    failure, and full state survival (exact same keys/ports/peers) across
    a complete container rebuild.

## Non-goals (for now)

No web UI, no multi-admin auth/RBAC, no clustering/HA, no non-Linux support.
These can be reconsidered once the single-node TUI tool is solid.

## Feature additions after initial validation (2026-10-02)

Three feature requests plus a cosmetic fix, from feedback after the first
round of live testing:

- **Pane focus fix.** Both panes rendered their cursor row in the same bold
  accent color regardless of which was actually focused — the only real
  signal was a subtler border/marker color difference. The inactive pane's
  cursor row now uses a dim `inactiveSelectedStyle` instead, so there's
  only ever one clearly "live" selection on screen.
- **Enable/disable (`t`)** for both tenants and peers, without touching a
  single key. Disabling a tenant tears its namespace down entirely;
  disabling a peer excludes it from the tenant's live WireGuard config.
  Re-enabling brings back the identical tunnel. Each direction only
  commits its database flag once the matching live action has actually
  succeeded, matching CreateTenant/DeleteTenant's existing discipline.
- **Isolation exceptions (`o`).** A tenant with `IsolatePeers` on can name
  destination IPs/CIDRs that stay reachable despite peer isolation — e.g.
  a shared jump host every road-warrior should still reach. Rendered as
  nftables accept rules placed *before* the isolation drop rule (`Ruleset`
  in `internal/netns/firewall.go`), since nft evaluates a chain's rules in
  order. Settable at tenant creation or edited live afterward.
- **Live peer stats.** The peers pane shows a connected/not indicator and
  last-handshake time, read from `wg show <iface> dump`
  (`internal/netns/stats.go`) on a 3-second tick plus immediately whenever
  peers (re)load.

This round required a real schema migration, not just a schema-string
edit — `CREATE TABLE IF NOT EXISTS` is a no-op against an already-existing
table, so the new `isolation_exceptions`/`enabled` columns never reached a
database created by the previous code version. **Confirmed live**: this
crash-looped the daemon with `no such column: isolation_exceptions` on
every single query immediately after redeploying. Fixed with explicit
`ALTER TABLE ... ADD COLUMN` migrations in `store.Open`, each tolerating
SQLite's "duplicate column name" error so a fresh database (where
`CREATE TABLE` already added the column) doesn't fail either. **Any future
schema change needs the same two-part treatment**: add the column to the
`schema` string *and* add a migration statement — the schema string alone
only ever helps a brand-new database.

Every new code path was validated live against the real container after
the migration fix, not just unit-tested:
- Pane-focus fix confirmed via raw ANSI escape codes (`tmux capture-pane -e`)
  showing the correct style swap between active/inactive panes.
- Tenant and peer enable/disable confirmed both directions against real
  `ip netns list`/`wg show`/the host DNAT table — namespace genuinely torn
  down and recreated, keys genuinely unchanged, port forwarding genuinely
  excluded/restored.
- Isolation exceptions confirmed via real `nft list ruleset` output showing
  the exact rule ordering (exception accept before isolation drop) for all
  three paths: set at creation, edited afterward, and cleared back out —
  with no rule duplication across any of it.
- Live stats confirmed rendering correctly (dot + handshake text) for
  peers with no real connection yet.
- Empty-selection warnings confirmed for the new `t`/`o` actions, matching
  the existing pattern for every other action.

## Two real bugs found from an actual phone connection (2026-10-02)

Martin connected a real device with full-tunnel AllowedIPs (`0.0.0.0/0`)
and found two things unit tests couldn't catch (neither involves fake-able
logic — both only show up against a real kernel and a real client):

1. **Internet traffic went nowhere past the tenant's own gateway.**
   Traceroute died at a `169.254.x.x` address — the link-local address
   `Ruleset`'s postrouting chain MASQUERADEs the WireGuard subnet to before
   routing out to the container's own namespace. Nothing then re-NATted
   *that* address before it left the container via Docker's bridge, since
   Docker's own NAT only covers its bridge subnet. Fixed with a second
   masquerade in `HostRuleset`'s new postrouting chain
   (`internal/netns/hostnat.go`). **Lesson for any future double-NAT hop
   added to this design**: every additional namespace boundary a packet
   crosses needs its own masquerade rule at that boundary — the previous
   hop's MASQUERADE only makes the packet valid *up to* the next hop, not
   beyond it.
2. **A peer's handshake reset whenever any other peer on the same tenant
   changed.** `wg setconf` (used by `SyncWireGuard`) tears down and
   recreates every peer in the file, including unchanged ones. Switched to
   `wg syncconf`, which diffs first — the same reason wg-quick itself uses
   syncconf for reloads, not setconf.

Also added: live traffic totals (overall, per-tenant, per-peer) via
`Service.AllPeerStats`, aggregating the existing per-tenant `PeerStats`
across every enabled tenant.

## Per-peer SDN-style routing — a real design gap, not just a feature (2026-10-02)

Martin asked how to edit a peer's AllowedIPs without recreating it,
explaining that AllowedIPs on the server's own peer entry is what actually
populates WireGuard's routing table for that peer — this is correct, and
exposed that **the server-side per-peer AllowedIPs was hardcoded to the
peer's own `/32`** (`syncTenantWireGuard` in `internal/app/service.go`),
never driven by the `AllowedIPs` field the operator could already set in
the TUI. That field only ever reached the *client's* exported config. So
the capability Martin assumed existed (route an extra prefix, e.g. a
subnet behind a peer acting as a gateway, to a specific peer) didn't exist
at all — nothing to "unlock", it had to be built.

**`RoutedPrefixes` is a deliberately separate new field, not a repurposing
of `AllowedIPs`.** Reusing the existing field would have been dangerous:
`AllowedIPs` commonly holds `"0.0.0.0/0, ::/0"` for full-tunnel clients,
and feeding that into the server's own peer AllowedIPs would make every
full-tunnel peer a catch-all default route — breaking every other peer's
connectivity (confirmed by reasoning through WireGuard's longest-prefix-
match routing before writing any code, not discovered by trial and error).
`RoutedPrefixes` is additive to the peer's own address, defaults to empty,
and existing peers are completely unaffected until an operator
deliberately sets one. Edited via the `r` ("edit routing") screen.

**If `AllowedIPs`/`RoutedPrefixes` semantics are ever touched again**: the
two fields answer different questions — "what should the *client* tunnel"
(`AllowedIPs`) vs "what should the *server* route to this specific peer"
(`RoutedPrefixes`, server's own address always included on top). Don't
collapse them into one field without re-deriving why that's unsafe (see
above) — this isn't a stylistic preference, it's the thing that keeps
multi-peer routing from breaking.

**Follow-up, same day:** shipping `RoutedPrefixes` immediately surfaced the
next layer of the same lesson — WireGuard's AllowedIPs only drives its
*internal* crypto-routing, it never touches the kernel's actual routing
table (that's `wg-quick`'s job normally, via `ip route add` per AllowedIPs
entry; this server talks to `wg` directly and never runs wg-quick). A
routed prefix showed up correctly in `wg show` while `ip route` inside the
namespace showed nothing for it. Fixed with `netns.Manager.
SyncRoutedPrefixes`, called from `syncTenantWireGuard`, which diffs the
desired route set against what's actually on `wg0` and adds/removes only
the difference (excluding the tenant's own connected subnet, which needs
no explicit route). **Any future field that maps to a WireGuard AllowedIPs
value needs to ask two separate questions**: does the crypto-routing need
updating (`wg syncconf`), and does the kernel's actual routing table need
updating too (`ip route`)? They are not the same operation and nothing
does the second one for you outside of wg-quick.

## Custom firewall rules — replacing "isolation exceptions" (2026-10-03)

Martin disliked the original isolation-exceptions field (one free-text,
comma-separated list of destination IPs/CIDRs that stayed reachable despite
`IsolatePeers`): no way to see or control evaluation order, address-only,
allow-only. He kept liking the base `IsolatePeers` toggle, but asked for
real firewall control — address-based forward blocks (not just allows) and
port-based rules — shown in the TUI in a way that's easy to read, add, and
reorder, and that's fully cleaned up when its tenant is deleted.

**Data model.** `firewall_rules` is a brand-new table (not a new column on
an existing one, so no `ALTER TABLE` migration was needed — `CREATE TABLE
IF NOT EXISTS` handles both fresh and pre-existing databases correctly for
a table that didn't exist before; this is the opposite case from
`isolation_exceptions`/`enabled`, which *did* need explicit migrations
because they were new columns on tables that already existed in the wild).
Columns: `id, tenant_id (FK ON DELETE CASCADE), priority, action
("allow"|"block"), address, port, protocol, created_at`, with `UNIQUE
(tenant_id, priority)`. The FK cascade means tenant deletion needs zero
extra app-layer cleanup code for rules — verified live: deleting a tenant
with a rule removed both the tenant row and its rule row in one step, same
as it already does for peers. The old `isolation_exceptions` column is left
physically in the schema/migrations as a harmless unused vestige rather
than attempting a `DROP COLUMN` migration (not worth the risk for a column
nothing reads anymore).

**Rendering.** `netns.FirewallRule{Action, Address, Port, Protocol}` is the
netns-level mirror of `store.FirewallRule` (same pattern as other
app↔netns mirrors like `PeerStat`). `Ruleset()` renders each rule, in
order, as one nft statement between `ct state established,related accept`
and the isolate-peers drop/default-subnet-accept lines:
- address only → `ip daddr <addr> <accept|drop>`
- port only, no protocol → `meta l4proto { tcp, udp } th dport <port>
  <accept|drop>` (matches both; `th dport` reads the transport header's
  destination port field at the same offset for tcp and udp)
- port + protocol → `<tcp|udp> dport <port> <accept|drop>`
- address + port → both match expressions combined on one line

Custom rules apply **unconditionally**, not just as exceptions to
`IsolatePeers` — this is the key behavioral difference from the old field.
A block for a specific address/port is a general firewall control; it
needs to hold whether or not peer isolation happens to be on. nftables
evaluates a chain top to bottom with first-match-wins, so an allow rule
placed before a later block (or before the isolation drop) overrides it,
exactly like an ACL.

**Priority / ordering.** `priority` is a plain integer, lowest evaluated
first; `ListFirewallRules` always returns `ORDER BY priority`, so "row
order in the list" *is* "evaluation order" — no separate priority number
needs to be shown. Move-up/move-down (`MoveFirewallRule`, bound to
shift+k/shift+j in the rules modal, chosen because j/k are already
cursor-navigation) swaps the selected rule's priority with its neighbor's
via `SwapFirewallRulePriorities`, which routes through a temporary
priority of `-1` mid-swap to avoid tripping the `UNIQUE(tenant_id,
priority)` constraint — cheaper than renumbering every rule for a tenant
on every reorder.

**TUI.** New `modalFirewallRules` (scrollable numbered list — number *is*
priority), `modalFirewallRuleForm` (reuses the existing generic `form`:
one toggle for Block/Allow, three text fields for Address/Port/Protocol),
and `modalConfirmDeleteFirewallRule`. Bound to the `o` key, replacing the
old exceptions prompt. Every mutation (add/delete/move) re-applies the
tenant's live firewall immediately and rolls the store change back if the
live apply fails — same rollback-on-failure discipline as every other
`Service` method.

### Two real bugs found during live testing, neither related to the firewall rules logic itself

1. **The space bar could never flip ANY toggle field, in the entire TUI,
   since this project's first commit.** `form.go`'s toggle handler checked
   `msg.String() == " "` to detect a space-bar press. bubbletea v2's
   `KeyPressMsg.String()` renders the space key as the literal word
   `"space"`, not a `" "` character — `Key.String()` falls through to
   `Keystroke()` whenever `Text == " "`, and `Keystroke()` explicitly
   writes `"space"` for `KeySpace`. So that comparison could never match.
   This existed for the `Preshared Key` and `Isolate Peers` toggles from
   day one; it went unnoticed because their defaults (`true`) happened to
   be what most operators wanted, so nobody needed to flip them. It became
   impossible to ignore the moment the firewall rule form's `Block` toggle
   (default `false`) needed to be flippable to `true` — without the fix,
   every firewall rule created through the TUI would silently be an allow
   rule no matter what the operator intended. Fixed by checking `"space"`
   instead of `" "`; confirmed live via tmux (space now correctly flips
   `[ ] no` → `[x] yes`) and with a new regression test,
   `TestFormToggleFlipsOnSpace`, constructing the exact `KeyPressMsg{Code:
   ' ', Text: " "}` bubbletea v2 actually sends. **Lesson: when matching
   `tea.KeyPressMsg.String()` for a key that isn't a plain printable
   letter/digit, check the library's actual `Keystroke()`/`String()`
   source for that key rather than assuming the naive literal value.**
2. **Reordering a rule left the list-cursor highlighting the wrong row.**
   `MoveFirewallRule` swaps priorities and the TUI just reloads the list by
   tenant ID — but the cursor is a numeric index, and after a reorder the
   rule that used to be at that index is a *different* rule. Moving a rule
   up then pressing "move up" again would silently start moving the wrong
   rule. Fixed by tracking the *moved rule's ID* (`model.firewallTrackID`)
   across the reload and re-deriving the cursor's position from where that
   ID landed in the freshly loaded list, instead of leaving the cursor at
   its old numeric index. Applied the same ID-tracking to "jump to the rule
   just added" after creating one, for consistency. Confirmed live via
   tmux: moving a rule up now keeps it highlighted at its new position, so
   repeated shift+k presses walk the same rule to the top.

### Firewall verification methodology — proving rules actually drop packets, not just that they render correctly

Unit tests (`internal/netns/firewall_test.go`) only check the *rendered nft
text* — they can't catch a case where the text is syntactically plausible
but semantically wrong (e.g. right rule, wrong chain/hook/order). Live
testing against the real tenant only proves `nft -f -` accepted the syntax
(no parse error), not that it actually blocks real traffic. To get real
proof, built a disposable three-namespace router topology inside the
running container (`fwtest-r` with veth links to `fwtest-a` and
`fwtest-b`, IP forwarding, no WireGuard involved at all) and applied the
*exact* nft text `Ruleset()` generates to `fwtest-r`'s forward chain, then
drove real TCP/UDP connections with `nc` between the two leaf namespaces.
Confirmed with real packets: an address+port+protocol block drops only
that flow (an adjacent port still connects fine); an address-only block
covers every port to that address; a port-only rule with no protocol
blocks both TCP and UDP; and an allow rule listed before a later blanket
block correctly overrides it (first-match-wins ordering holds under real
traffic, not just in rendered text). Namespaces were torn down after.
**This disposable-topology pattern is reusable for verifying any future
nftables change without touching a real tenant** — three plain namespaces
and veth pairs are enough to exercise a forward-chain ruleset end to end.
