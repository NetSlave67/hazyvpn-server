// Package config loads HazyVPN Server's operator-facing settings: where it
// stores state, and how it sends email. Everything here is read once at
// startup; tenant/peer settings live in the database, not here.
package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"gopkg.in/yaml.v3"
)

// Config is HazyVPN Server's top-level configuration, loaded from
// /etc/hazyvpn-server/config.yaml with environment variable overrides
// (HAZYVPN_<FIELD>, e.g. HAZYVPN_SMTP_PASSWORD) so secrets don't have to
// live on disk in plaintext if the operator prefers.
type Config struct {
	// DataDir holds the SQLite database and the server's master encryption
	// key. Defaults to /var/lib/hazyvpn-server.
	DataDir string `yaml:"data_dir"`
	// PublicHost is the hostname or IP peers use to reach this server; it's
	// combined with each tenant's listen port to form that peer's Endpoint.
	PublicHost string `yaml:"public_host"`
	// ExportDir is where downloaded configs/QR codes/backups are written.
	// Empty means DataDir/exports (see ExportDirOrDefault).
	ExportDir string     `yaml:"export_dir"`
	SMTP      SMTPConfig `yaml:"smtp"`
}

// SMTPConfig mirrors internal/mail.SMTPConfig but as a serializable shape;
// cmd/hazyvpn-server converts between the two at startup.
type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	From     string `yaml:"from"`
	UseTLS   bool   `yaml:"use_tls"`
}

// Default returns a Config with sane out-of-the-box values for the Docker
// deployment target.
func Default() Config {
	return Config{
		DataDir: "/var/lib/hazyvpn-server",
		SMTP: SMTPConfig{
			Port:   587,
			UseTLS: true,
		},
	}
}

// Load reads path (if it exists) over Default(), then applies environment
// variable overrides. A missing file is not an error — the server can run
// on defaults plus environment variables alone.
func Load(path string) (Config, error) {
	cfg := Default()

	data, err := os.ReadFile(path)
	if err != nil {
		if !os.IsNotExist(err) {
			return cfg, fmt.Errorf("config: reading %s: %w", path, err)
		}
	} else if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("config: parsing %s: %w", path, err)
	}

	applyEnvOverrides(&cfg)

	if cfg.DataDir == "" {
		return cfg, fmt.Errorf("config: data_dir must not be empty")
	}
	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	if v, ok := os.LookupEnv("HAZYVPN_DATA_DIR"); ok {
		cfg.DataDir = v
	}
	if v, ok := os.LookupEnv("HAZYVPN_PUBLIC_HOST"); ok {
		cfg.PublicHost = v
	}
	if v, ok := os.LookupEnv("HAZYVPN_EXPORT_DIR"); ok {
		cfg.ExportDir = v
	}
	if v, ok := os.LookupEnv("HAZYVPN_SMTP_HOST"); ok {
		cfg.SMTP.Host = v
	}
	if v, ok := os.LookupEnv("HAZYVPN_SMTP_PORT"); ok {
		if port, err := strconv.Atoi(v); err == nil {
			cfg.SMTP.Port = port
		}
	}
	if v, ok := os.LookupEnv("HAZYVPN_SMTP_USERNAME"); ok {
		cfg.SMTP.Username = v
	}
	if v, ok := os.LookupEnv("HAZYVPN_SMTP_PASSWORD"); ok {
		cfg.SMTP.Password = v
	}
	if v, ok := os.LookupEnv("HAZYVPN_SMTP_FROM"); ok {
		cfg.SMTP.From = v
	}
}

// MasterKeyPath is where the AES master key used to encrypt stored
// WireGuard keys lives.
func (c Config) MasterKeyPath() string {
	return filepath.Join(c.DataDir, "server.key")
}

// DatabasePath is where the SQLite database lives.
func (c Config) DatabasePath() string {
	return filepath.Join(c.DataDir, "db.sqlite")
}

// ExportDirOrDefault returns ExportDir, or DataDir/exports if unset.
func (c Config) ExportDirOrDefault() string {
	if c.ExportDir != "" {
		return c.ExportDir
	}
	return filepath.Join(c.DataDir, "exports")
}
