// Package store persists tenants and peers in a local SQLite database.
// Peer private keys and preshared keys are encrypted at rest via
// internal/cryptutil before they ever touch disk.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"hazyvpn-server/internal/cryptutil"
)

const schema = `
CREATE TABLE IF NOT EXISTS tenants (
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

CREATE TABLE IF NOT EXISTS peers (
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

// Store wraps a SQLite connection plus the master key used to seal/open
// peer and tenant private keys.
type Store struct {
	db     *sql.DB
	sealer *cryptutil.Sealer
}

// ErrNotFound is returned when a lookup by ID/name matches no row.
var ErrNotFound = errors.New("store: not found")

// Open opens (creating if necessary) the SQLite database at path and applies
// the schema. sealer encrypts/decrypts private and preshared keys at rest.
func Open(path string, sealer *cryptutil.Sealer) (*Store, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("store: opening database: %w", err)
	}
	// SQLite only supports one writer at a time; the TUI is single-process
	// and single-user, so serialize rather than fight busy-database errors.
	db.SetMaxOpenConns(1)

	if _, err := db.Exec("PRAGMA foreign_keys = ON;"); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: enabling foreign keys: %w", err)
	}
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: applying schema: %w", err)
	}
	return &Store{db: db, sealer: sealer}, nil
}

// Close closes the underlying database connection.
func (s *Store) Close() error {
	return s.db.Close()
}

// friendlyConflictError turns a raw SQLite UNIQUE constraint error into a
// specific, actionable message naming what collided, instead of a generic
// failure — e.g. "a peer named \"alice\" already exists in this tenant"
// rather than "UNIQUE constraint failed: peers.tenant_id, peers.name".
func friendlyConflictError(err error, kind string, fields map[string]string) error {
	msg := err.Error()
	if !strings.Contains(msg, "UNIQUE constraint failed") {
		return err
	}
	for column, label := range fields {
		if strings.Contains(msg, column) {
			return fmt.Errorf("store: %s with %s already exists", kind, label)
		}
	}
	return fmt.Errorf("store: duplicate %s: %w", kind, err)
}

// --- Tenants ---------------------------------------------------------------

func (s *Store) CreateTenant(ctx context.Context, in TenantInput) (*Tenant, error) {
	sealedKey, err := s.sealer.SealString(in.ServerPrivateKey)
	if err != nil {
		return nil, fmt.Errorf("store: sealing server private key: %w", err)
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO tenants (name, subnet, listen_port, server_private_key, server_public_key,
			dns, allowed_ips, keepalive, psk_required, isolate_peers)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.Name, in.Subnet, in.ListenPort, sealedKey, in.ServerPublicKey,
		in.DNS, in.AllowedIPs, in.Keepalive, boolToInt(in.PSKRequired), boolToInt(in.IsolatePeers),
	)
	if err != nil {
		return nil, friendlyConflictError(err, "a tenant", map[string]string{
			"tenants.name": fmt.Sprintf("the name %q", in.Name),
		})
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("store: reading new tenant id: %w", err)
	}
	return s.GetTenant(ctx, id)
}

func (s *Store) scanTenant(row interface {
	Scan(dest ...any) error
}) (*Tenant, error) {
	var t Tenant
	var sealedKey []byte
	var psk, isolate int
	var createdAt time.Time
	if err := row.Scan(&t.ID, &t.Name, &t.Subnet, &t.ListenPort, &sealedKey, &t.ServerPublicKey,
		&t.DNS, &t.AllowedIPs, &t.Keepalive, &psk, &isolate, &createdAt); err != nil {
		return nil, err
	}
	key, err := s.sealer.OpenString(sealedKey)
	if err != nil {
		return nil, fmt.Errorf("store: decrypting server private key for tenant %q: %w", t.Name, err)
	}
	t.ServerPrivateKey = key
	t.PSKRequired = psk != 0
	t.IsolatePeers = isolate != 0
	t.CreatedAt = createdAt
	return &t, nil
}

func (s *Store) GetTenant(ctx context.Context, id int64) (*Tenant, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, subnet, listen_port, server_private_key, server_public_key,
			dns, allowed_ips, keepalive, psk_required, isolate_peers, created_at
		FROM tenants WHERE id = ?`, id)
	t, err := s.scanTenant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

func (s *Store) GetTenantByName(ctx context.Context, name string) (*Tenant, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, name, subnet, listen_port, server_private_key, server_public_key,
			dns, allowed_ips, keepalive, psk_required, isolate_peers, created_at
		FROM tenants WHERE name = ?`, name)
	t, err := s.scanTenant(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return t, err
}

func (s *Store) ListTenants(ctx context.Context) ([]Tenant, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, name, subnet, listen_port, server_private_key, server_public_key,
			dns, allowed_ips, keepalive, psk_required, isolate_peers, created_at
		FROM tenants ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Tenant
	for rows.Next() {
		t, err := s.scanTenant(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *t)
	}
	return out, rows.Err()
}

func (s *Store) DeleteTenant(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM tenants WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

// --- Peers -------------------------------------------------------------

func (s *Store) CreatePeer(ctx context.Context, in PeerInput) (*Peer, error) {
	sealedPriv, err := s.sealer.SealString(in.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("store: sealing peer private key: %w", err)
	}
	var sealedPSK []byte
	if in.PresharedKey != "" {
		sealedPSK, err = s.sealer.SealString(in.PresharedKey)
		if err != nil {
			return nil, fmt.Errorf("store: sealing preshared key: %w", err)
		}
	}

	res, err := s.db.ExecContext(ctx, `
		INSERT INTO peers (tenant_id, name, address, public_key, private_key, preshared_key,
			allowed_ips, dns, keepalive)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		in.TenantID, in.Name, in.Address, in.PublicKey, sealedPriv, nullableBytes(sealedPSK),
		in.AllowedIPs, in.DNS, in.Keepalive,
	)
	if err != nil {
		return nil, friendlyConflictError(err, "a peer", map[string]string{
			"peers.address":    fmt.Sprintf("the address %q", in.Address),
			"peers.name":       fmt.Sprintf("the name %q", in.Name),
			"peers.public_key": "that public key",
		})
	}
	id, err := res.LastInsertId()
	if err != nil {
		return nil, fmt.Errorf("store: reading new peer id: %w", err)
	}
	return s.GetPeer(ctx, id)
}

func (s *Store) scanPeer(row interface {
	Scan(dest ...any) error
}) (*Peer, error) {
	var p Peer
	var sealedPriv []byte
	var sealedPSK []byte
	var createdAt time.Time
	if err := row.Scan(&p.ID, &p.TenantID, &p.Name, &p.Address, &p.PublicKey, &sealedPriv, &sealedPSK,
		&p.AllowedIPs, &p.DNS, &p.Keepalive, &createdAt); err != nil {
		return nil, err
	}
	priv, err := s.sealer.OpenString(sealedPriv)
	if err != nil {
		return nil, fmt.Errorf("store: decrypting private key for peer %q: %w", p.Name, err)
	}
	p.PrivateKey = priv
	psk, err := s.sealer.OpenString(sealedPSK)
	if err != nil {
		return nil, fmt.Errorf("store: decrypting preshared key for peer %q: %w", p.Name, err)
	}
	p.PresharedKey = psk
	p.CreatedAt = createdAt
	return &p, nil
}

func (s *Store) GetPeer(ctx context.Context, id int64) (*Peer, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, tenant_id, name, address, public_key, private_key, preshared_key,
			allowed_ips, dns, keepalive, created_at
		FROM peers WHERE id = ?`, id)
	p, err := s.scanPeer(row)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return p, err
}

func (s *Store) ListPeers(ctx context.Context, tenantID int64) ([]Peer, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, tenant_id, name, address, public_key, private_key, preshared_key,
			allowed_ips, dns, keepalive, created_at
		FROM peers WHERE tenant_id = ? ORDER BY name`, tenantID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Peer
	for rows.Next() {
		p, err := s.scanPeer(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, *p)
	}
	return out, rows.Err()
}

func (s *Store) DeletePeer(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM peers WHERE id = ?`, id)
	if err != nil {
		return err
	}
	n, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if n == 0 {
		return ErrNotFound
	}
	return nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nullableBytes(b []byte) any {
	if len(b) == 0 {
		return nil
	}
	return b
}
