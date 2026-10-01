package wgconf

import "testing"

func TestGenerateKeypairProducesDistinctKeys(t *testing.T) {
	a, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	b, err := GenerateKeypair()
	if err != nil {
		t.Fatalf("GenerateKeypair: %v", err)
	}
	if a.Private.String() == b.Private.String() {
		t.Fatal("two generated keypairs produced identical private keys")
	}
	if a.Public.String() != a.Private.PublicKey().String() {
		t.Fatal("Keypair.Public does not match Private.PublicKey()")
	}
}

func TestRenderPeerConfigRoundTrip(t *testing.T) {
	kp, _ := GenerateKeypair()
	server, _ := GenerateKeypair()
	psk, _ := GeneratePresharedKey()

	rendered := RenderPeerConfig(PeerConfig{
		Name:                "alice-laptop",
		PrivateKey:          kp.Private.String(),
		Address:             "10.8.0.2/24",
		DNS:                 "1.1.1.1",
		ServerPublicKey:     server.Public.String(),
		PresharedKey:        psk.String(),
		Endpoint:            "vpn.example.net:51820",
		AllowedIPs:          "0.0.0.0/0, ::/0",
		PersistentKeepalive: 25,
	})

	parsed, err := Parse(rendered)
	if err != nil {
		t.Fatalf("Parse(rendered peer config): %v", err)
	}
	if parsed.Interface["PrivateKey"] != kp.Private.String() {
		t.Errorf("PrivateKey round-trip mismatch")
	}
	if parsed.Interface["Address"] != "10.8.0.2/24" {
		t.Errorf("Address round-trip mismatch: %q", parsed.Interface["Address"])
	}
	if len(parsed.Peers) != 1 {
		t.Fatalf("expected 1 peer section, got %d", len(parsed.Peers))
	}
	if parsed.Peers[0]["PublicKey"] != server.Public.String() {
		t.Errorf("server PublicKey round-trip mismatch")
	}
	if parsed.Peers[0]["PersistentKeepalive"] != "25" {
		t.Errorf("PersistentKeepalive round-trip mismatch: %q", parsed.Peers[0]["PersistentKeepalive"])
	}
}

func TestRenderServerConfigWithMultiplePeers(t *testing.T) {
	server, _ := GenerateKeypair()
	p1, _ := GenerateKeypair()
	p2, _ := GenerateKeypair()

	rendered := RenderServerConfig(ServerInterfaceConfig{
		PrivateKey: server.Private.String(),
		Address:    "10.8.0.1/24",
		ListenPort: 51820,
		Peers: []ServerPeerSection{
			{Name: "alice", PublicKey: p1.Public.String(), AllowedIPs: "10.8.0.2/32"},
			{Name: "bob", PublicKey: p2.Public.String(), AllowedIPs: "10.8.0.3/32"},
		},
	})

	parsed, err := Parse(rendered)
	if err != nil {
		t.Fatalf("Parse(rendered server config): %v", err)
	}
	if len(parsed.Peers) != 2 {
		t.Fatalf("expected 2 peer sections, got %d", len(parsed.Peers))
	}
	if parsed.Peers[1]["AllowedIPs"] != "10.8.0.3/32" {
		t.Errorf("second peer AllowedIPs mismatch: %q", parsed.Peers[1]["AllowedIPs"])
	}
}

func TestParseRejectsMissingInterfaceSection(t *testing.T) {
	_, err := Parse("[Peer]\nPublicKey = abc\n")
	if err == nil {
		t.Fatal("expected error for config with no [Interface] section")
	}
}

func TestDangerousHooksDetected(t *testing.T) {
	text := "[Interface]\nPrivateKey = abc\nPostUp = iptables -A FORWARD -j ACCEPT\n"
	parsed, err := Parse(text)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	hooks := parsed.DangerousHooks()
	if len(hooks) != 1 || hooks[0] != "PostUp" {
		t.Fatalf("DangerousHooks = %v, want [PostUp]", hooks)
	}
}

func TestDangerousHooksCleanConfig(t *testing.T) {
	text := "[Interface]\nPrivateKey = abc\nAddress = 10.8.0.2/24\n"
	parsed, err := Parse(text)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if hooks := parsed.DangerousHooks(); len(hooks) != 0 {
		t.Fatalf("DangerousHooks = %v, want none", hooks)
	}
}
