// Package mail emails a rendered WireGuard config (and optionally its QR
// code) to a peer, using operator-supplied SMTP settings. Credentials are
// never logged.
package mail

import (
	"bytes"
	"fmt"

	gomail "github.com/wneessen/go-mail"
)

// SMTPConfig holds the server's outgoing mail settings.
type SMTPConfig struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	// UseTLS selects mandatory STARTTLS; set false only for internal
	// relays that don't support it.
	UseTLS bool
}

// PeerConfigMail is the content of a single config-delivery email.
type PeerConfigMail struct {
	To          string
	TenantName  string
	PeerName    string
	ConfigText  string // rendered .conf contents
	ConfigQRPNG []byte // optional; nil to omit the QR attachment
}

// Send delivers a peer's WireGuard config (and QR code, if provided) as
// email attachments.
func Send(cfg SMTPConfig, m PeerConfigMail) error {
	if cfg.Host == "" {
		return fmt.Errorf("mail: SMTP host is not configured")
	}

	msg := gomail.NewMsg()
	if err := msg.From(cfg.From); err != nil {
		return fmt.Errorf("mail: invalid From address %q: %w", cfg.From, err)
	}
	if err := msg.To(m.To); err != nil {
		return fmt.Errorf("mail: invalid To address %q: %w", m.To, err)
	}
	msg.Subject(fmt.Sprintf("HazyVPN config: %s / %s", m.TenantName, m.PeerName))
	msg.SetBodyString(gomail.TypeTextPlain, fmt.Sprintf(
		"Attached is your WireGuard configuration for %q on tenant %q.\n\n"+
			"Import it into the WireGuard app, or scan the attached QR code on mobile.\n",
		m.PeerName, m.TenantName,
	))

	confName := fmt.Sprintf("%s-%s.conf", m.TenantName, m.PeerName)
	if err := msg.AttachReader(confName, bytes.NewReader([]byte(m.ConfigText))); err != nil {
		return fmt.Errorf("mail: attaching config: %w", err)
	}
	if len(m.ConfigQRPNG) > 0 {
		qrName := fmt.Sprintf("%s-%s-qr.png", m.TenantName, m.PeerName)
		if err := msg.AttachReader(qrName, bytes.NewReader(m.ConfigQRPNG)); err != nil {
			return fmt.Errorf("mail: attaching QR code: %w", err)
		}
	}

	opts := []gomail.Option{gomail.WithPort(cfg.Port)}
	if cfg.UseTLS {
		opts = append(opts, gomail.WithTLSPolicy(gomail.TLSMandatory))
	} else {
		opts = append(opts, gomail.WithTLSPolicy(gomail.NoTLS))
	}
	if cfg.Username != "" {
		opts = append(opts, gomail.WithSMTPAuth(gomail.SMTPAuthAutoDiscover),
			gomail.WithUsername(cfg.Username), gomail.WithPassword(cfg.Password))
	}

	client, err := gomail.NewClient(cfg.Host, opts...)
	if err != nil {
		return fmt.Errorf("mail: building SMTP client: %w", err)
	}
	if err := client.DialAndSend(msg); err != nil {
		return fmt.Errorf("mail: sending to %s: %w", m.To, err)
	}
	return nil
}
