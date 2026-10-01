package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadMissingFileReturnsDefaults(t *testing.T) {
	cfg, err := Load(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DataDir != Default().DataDir {
		t.Fatalf("expected default data dir, got %q", cfg.DataDir)
	}
}

func TestLoadParsesYAMLFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	yaml := "data_dir: /custom/data\npublic_host: vpn.example.net\nsmtp:\n  host: smtp.example.net\n  port: 465\n  from: vpn@example.net\n  use_tls: true\n"
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DataDir != "/custom/data" {
		t.Fatalf("DataDir = %q, want /custom/data", cfg.DataDir)
	}
	if cfg.PublicHost != "vpn.example.net" {
		t.Fatalf("PublicHost = %q", cfg.PublicHost)
	}
	if cfg.SMTP.Port != 465 {
		t.Fatalf("SMTP.Port = %d, want 465", cfg.SMTP.Port)
	}
}

func TestEnvOverridesTakePrecedence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte("data_dir: /from/file\n"), 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	t.Setenv("HAZYVPN_DATA_DIR", "/from/env")

	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.DataDir != "/from/env" {
		t.Fatalf("DataDir = %q, want /from/env (env should override file)", cfg.DataDir)
	}
}

func TestMasterKeyAndDatabasePaths(t *testing.T) {
	cfg := Config{DataDir: "/var/lib/hazyvpn-server"}
	if got := cfg.MasterKeyPath(); got != "/var/lib/hazyvpn-server/server.key" {
		t.Fatalf("MasterKeyPath = %q", got)
	}
	if got := cfg.DatabasePath(); got != "/var/lib/hazyvpn-server/db.sqlite" {
		t.Fatalf("DatabasePath = %q", got)
	}
}
