package main

import (
	"fmt"
	"strconv"

	"hazyvpn-server/internal/app"
	"hazyvpn-server/internal/store"
)

func newTenantFormModel(subnet string, port int) *form {
	f := newForm("New Tenant")
	f.addText("Name", "", "")
	f.addText("Subnet", "CIDR, e.g. 10.8.0.0/24", subnet)
	f.addText("Listen Port", "UDP port peers connect to", strconv.Itoa(port))
	f.addText("DNS", "optional, e.g. 1.1.1.1", "")
	f.addText("Keepalive", "seconds", "25")
	f.addToggle("Preshared Key", "default on for new peers", true)
	f.addToggle("Isolate Peers", "block peers from reaching each other", true)
	f.focusField()
	return f
}

func tenantParamsFromForm(f *form) (app.CreateTenantParams, error) {
	name := f.value("Name")
	if name == "" {
		return app.CreateTenantParams{}, fmt.Errorf("name is required")
	}
	port, err := strconv.Atoi(f.value("Listen Port"))
	if err != nil {
		return app.CreateTenantParams{}, fmt.Errorf("listen port must be a number")
	}
	keepalive := 25
	if v := f.value("Keepalive"); v != "" {
		keepalive, err = strconv.Atoi(v)
		if err != nil {
			return app.CreateTenantParams{}, fmt.Errorf("keepalive must be a number")
		}
	}
	return app.CreateTenantParams{
		Name:         name,
		Subnet:       f.value("Subnet"),
		ListenPort:   port,
		DNS:          f.value("DNS"),
		Keepalive:    keepalive,
		PSKRequired:  f.toggle("Preshared Key"),
		IsolatePeers: f.toggle("Isolate Peers"),
	}, nil
}

func newPeerFormModel(tenant *store.Tenant, suggestedAddr string) *form {
	f := newForm("Add Peer — " + tenant.Name)
	f.addText("Name", "", "")
	f.addText("Address", "auto-suggested, editable", suggestedAddr)
	f.addText("Allowed IPs", "", tenant.AllowedIPs)
	f.addText("DNS", "", tenant.DNS)
	f.addText("Keepalive", "seconds", strconv.Itoa(tenant.Keepalive))
	f.addToggle("Preshared Key", "", tenant.PSKRequired)
	f.focusField()
	return f
}

func peerParamsFromForm(f *form, tenantID int64) (app.AddPeerParams, error) {
	name := f.value("Name")
	if name == "" {
		return app.AddPeerParams{}, fmt.Errorf("name is required")
	}
	keepalive := 0
	if v := f.value("Keepalive"); v != "" {
		var err error
		keepalive, err = strconv.Atoi(v)
		if err != nil {
			return app.AddPeerParams{}, fmt.Errorf("keepalive must be a number")
		}
	}
	withPSK := f.toggle("Preshared Key")
	return app.AddPeerParams{
		TenantID:      tenantID,
		Name:          name,
		Address:       f.value("Address"),
		AllowedIPs:    f.value("Allowed IPs"),
		DNS:           f.value("DNS"),
		Keepalive:     keepalive,
		WithPreshared: &withPSK,
	}, nil
}

func newPromptForm(title, label, help, value string) *form {
	f := newForm(title)
	f.addText(label, help, value)
	f.focusField()
	return f
}
