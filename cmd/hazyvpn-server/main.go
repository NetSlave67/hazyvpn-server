package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	tea "charm.land/bubbletea/v2"

	"hazyvpn-server/internal/app"
	"hazyvpn-server/internal/config"
	"hazyvpn-server/internal/cryptutil"
	"hazyvpn-server/internal/mail"
	"hazyvpn-server/internal/netns"
	"hazyvpn-server/internal/store"
)

var version = "dev"

const defaultConfigPath = "/etc/hazyvpn-server/config.yaml"

func main() {
	args := os.Args[1:]
	for _, a := range args {
		switch a {
		case "--version", "-v":
			fmt.Println("hazyvpn-server " + displayVersion())
			return
		case "--help", "-h":
			printUsage()
			return
		}
	}

	var err error
	if len(args) > 0 && args[0] == "daemon" {
		err = runDaemon()
	} else {
		err = runTUI()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

// bootstrap opens everything every mode needs: config, encrypted store, and
// the namespace manager, wired into a Service.
func bootstrap() (*app.Service, config.Config, func(), error) {
	configPath := defaultConfigPath
	if v := os.Getenv("HAZYVPN_CONFIG"); v != "" {
		configPath = v
	}
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, cfg, nil, fmt.Errorf("loading config: %w", err)
	}
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, cfg, nil, fmt.Errorf("creating data dir: %w", err)
	}

	masterKey, err := cryptutil.LoadOrCreateMasterKey(cfg.MasterKeyPath())
	if err != nil {
		return nil, cfg, nil, fmt.Errorf("loading master key: %w", err)
	}
	sealer := cryptutil.NewSealer(masterKey)

	st, err := store.Open(cfg.DatabasePath(), sealer)
	if err != nil {
		return nil, cfg, nil, fmt.Errorf("opening database: %w", err)
	}

	netMgr := netns.NewManager()
	if err := netMgr.EnsureHostForwarding(); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not enable IPv4 forwarding: %v\n", err)
	}

	smtp := mail.SMTPConfig{
		Host: cfg.SMTP.Host, Port: cfg.SMTP.Port,
		Username: cfg.SMTP.Username, Password: cfg.SMTP.Password,
		From: cfg.SMTP.From, UseTLS: cfg.SMTP.UseTLS,
	}
	svc := app.New(st, netMgr, cfg.PublicHost, smtp)
	return svc, cfg, func() { st.Close() }, nil
}

// runDaemon is the container's long-running main process: it reconciles
// every tenant's namespace against the database (recreating any that a
// container restart wiped out) and then idles until it's told to stop.
// It never runs the TUI — a separate `docker exec` invocation does that —
// so quitting the TUI can never take the tenants' namespaces down with it.
func runDaemon() error {
	svc, _, closeFn, err := bootstrap()
	if err != nil {
		return err
	}
	defer closeFn()

	if err := svc.Reconcile(context.Background()); err != nil {
		return fmt.Errorf("reconciling tenants at startup: %w", err)
	}
	fmt.Println("hazyvpn-server daemon: tenants reconciled, idling")

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	<-sig
	fmt.Println("hazyvpn-server daemon: shutting down")
	return nil
}

// runTUI launches the interactive admin TUI. It also reconciles at startup
// so it works correctly even when run standalone (outside the daemon/
// docker-exec split), at the cost of a harmless no-op when the daemon
// already reconciled.
func runTUI() error {
	svc, cfg, closeFn, err := bootstrap()
	if err != nil {
		return err
	}
	defer closeFn()

	if err := svc.Reconcile(context.Background()); err != nil {
		return fmt.Errorf("reconciling tenants at startup: %w", err)
	}

	initColors()
	p := tea.NewProgram(newModel(svc, cfg.PublicHost, cfg.ExportDirOrDefault()))
	_, err = p.Run()
	return err
}

func displayVersion() string {
	if version == "dev" {
		return "dev"
	}
	return "v" + version
}

func printUsage() {
	fmt.Println(`hazyvpn-server - a multi-tenant WireGuard server manager

Usage:
  hazyvpn-server            launch the admin TUI
  hazyvpn-server daemon     run the long-lived reconciler (used as the
                            container's main process; keeps tenant
                            namespaces up independent of the TUI)
  hazyvpn-server --version  print the version
  hazyvpn-server --help     show this message

Configuration is read from /etc/hazyvpn-server/config.yaml (override the
path with HAZYVPN_CONFIG) with environment variable overrides — see
instructions/architecture.md for details.

Keys (inside the TUI):
  j/k, ↑/↓   move          tab   switch pane
  n          new tenant    a     add peer
  x          delete        v     view config
  g          show QR       c     copy to clipboard
  d          export        i     import
  e          email config  ?     help
  q          quit`)
}
