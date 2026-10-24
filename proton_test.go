package main

import (
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testProtonKey      = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
	testProtonServerJS = `{
  "version": 4,
  "servers": [
    {
      "vpn": "wireguard",
      "country": "United States",
      "city": "San Jose",
      "server_name": "US-FREE#1",
      "hostname": "node-us-1.protonvpn.net",
      "wgpubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "free": true,
      "ips": ["1.2.3.4"]
    },
    {
      "vpn": "wireguard",
      "country": "United States",
      "city": "San Jose",
      "server_name": "US-FREE#2",
      "hostname": "node-us-2.protonvpn.net",
      "wgpubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "free": true,
      "ips": ["1.2.3.5"]
    },
    {
      "vpn": "wireguard",
      "country": "United States",
      "city": "Miami",
      "server_name": "US-FREE#3",
      "hostname": "node-us-3.protonvpn.net",
      "wgpubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "free": true,
      "ips": ["1.2.3.6"]
    },
    {
      "vpn": "wireguard",
      "country": "Canada",
      "city": "Montreal",
      "server_name": "CA-FREE#1",
      "hostname": "node-ca-1.protonvpn.net",
      "wgpubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "free": true,
      "ips": ["1.2.3.7"]
    },
    {
      "vpn": "wireguard",
      "country": "Singapore",
      "city": "Singapore",
      "server_name": "SG-FREE#1",
      "hostname": "node-sg-1.protonvpn.net",
      "wgpubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "free": true,
      "ips": []
    },
    {
      "vpn": "wireguard",
      "country": "Germany",
      "city": "Berlin",
      "server_name": "DE#1",
      "hostname": "node-de-1.protonvpn.net",
      "wgpubkey": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
      "free": false,
      "ips": ["1.2.3.8"]
    },
    {
      "vpn": "openvpn",
      "country": "United States",
      "city": "New York",
      "server_name": "US-FREE#4",
      "hostname": "node-us-4.protonvpn.net",
      "free": true,
      "ips": ["1.2.3.9"]
    },
    {
      "vpn": "wireguard",
      "country": "Japan",
      "city": "Tokyo",
      "server_name": "JP-FREE#1",
      "hostname": "node-jp-1.protonvpn.net",
      "wgpubkey": "not-a-valid-key",
      "free": true,
      "ips": ["1.2.3.10"]
    }
  ]
}`
)

func testProtonServers(t *testing.T) []protonServer {
	t.Helper()
	servers, err := parseProtonServers([]byte(testProtonServerJS))
	if err != nil {
		t.Fatal(err)
	}
	return servers
}

func TestParseProtonServersFreeOnly(t *testing.T) {
	servers := testProtonServers(t)
	if len(servers) != 5 {
		t.Fatalf("servers = %d, want 5: %+v", len(servers), servers)
	}
	for _, server := range servers {
		if !server.Free || server.VPN != "wireguard" {
			t.Fatalf("non-free or non-WireGuard server was accepted: %+v", server)
		}
		if server.Country == "Germany" {
			t.Fatal("paid German server was accepted")
		}
		if server.ServerName == "US-FREE#4" {
			t.Fatal("free OpenVPN server was accepted")
		}
	}
}

func TestProtonServerEndpoint(t *testing.T) {
	server := protonServer{IPs: []string{"2001:db8::1", "1.2.3.4"}}
	if got, err := server.endpoint(); err != nil || got != "1.2.3.4" {
		t.Fatalf("endpoint = %q, %v; want IPv4", got, err)
	}

	server = protonServer{IPs: []string{"2001:db8::1"}}
	if got, err := server.endpoint(); err != nil || got != "2001:db8::1" {
		t.Fatalf("endpoint = %q, %v; want IPv6", got, err)
	}

	server = protonServer{Hostname: "node-example.protonvpn.net"}
	if got, err := server.endpoint(); err != nil || got != "node-example.protonvpn.net" {
		t.Fatalf("endpoint = %q, %v; want hostname", got, err)
	}

	server = protonServer{ServerName: "US-FREE#9"}
	if _, err := server.endpoint(); err == nil {
		t.Fatal("expected an error for a server without an endpoint")
	}
}

func TestProtonCitySlug(t *testing.T) {
	tests := map[string]string{
		"San Jose":    "san-jose",
		"Mexico City": "mexico-city",
		"New York":    "new-york",
		"  Tokyo  ":   "tokyo",
		"St. Louis":   "st-louis",
	}
	for in, want := range tests {
		if got := protonCitySlug(in); got != want {
			t.Errorf("protonCitySlug(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveProtonChoice(t *testing.T) {
	servers := testProtonServers(t)
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "any", false},
		{"ANY", "any", false},
		{"us", "us", false},
		{"US", "us", false},
		{"us/san-jose", "us/san-jose", false},
		{"us/San Jose", "us/san-jose", false},
		{"ca/montreal", "ca/montreal", false},
		{"de", "", true}, // paid only
		{"de/berlin", "", true},
		{"us/atlantis", "", true},
		{"usa", "", true},
		{"us/", "", true},
	}
	for _, test := range tests {
		got, err := resolveProtonChoice(test.in, servers)
		if (err != nil) != test.wantErr {
			t.Errorf("resolveProtonChoice(%q) error = %v, wantErr %v", test.in, err, test.wantErr)
			continue
		}
		if !test.wantErr && got != test.want {
			t.Errorf("resolveProtonChoice(%q) = %q, want %q", test.in, got, test.want)
		}
	}

	choices := protonCityChoices(servers)
	for i := 0; i < 20; i++ {
		got, err := resolveProtonChoice("random", servers)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, choice := range choices {
			if choice == got {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("random choice %q is not a free city choice", got)
		}
	}
}

func TestSelectProtonServer(t *testing.T) {
	servers := testProtonServers(t)
	for i := 0; i < 50; i++ {
		server, err := selectProtonServer(servers, "us/san-jose")
		if err != nil {
			t.Fatal(err)
		}
		if server.Country != "United States" || server.City != "San Jose" {
			t.Fatalf("selected %+v, want San Jose", server)
		}
	}

	for i := 0; i < 50; i++ {
		server, err := selectProtonServer(servers, "ca")
		if err != nil {
			t.Fatal(err)
		}
		if server.Country != "Canada" {
			t.Fatalf("selected %+v, want Canada", server)
		}
	}

	if _, err := selectProtonServer(servers, "de/berlin"); err == nil {
		t.Fatal("expected no match for a paid-only location")
	}
}

func TestProtonLocationChoices(t *testing.T) {
	choices := protonLocationChoices(testProtonServers(t))
	want := []string{
		"any",
		"ca", "ca/montreal",
		"sg", "sg/singapore",
		"us", "us/miami", "us/san-jose",
	}
	if len(choices) != len(want) {
		t.Fatalf("choices = %+v, want %v", choices, want)
	}
	for i, code := range want {
		if choices[i].Code != code {
			t.Fatalf("choices[%d].Code = %q, want %q", i, choices[i].Code, code)
		}
	}
	if choices[2].Label != "Montreal" {
		t.Fatalf("Montreal label = %q", choices[2].Label)
	}
	if choices[len(choices)-1].Label != "San Jose (2 servers)" {
		t.Fatalf("San Jose label = %q", choices[len(choices)-1].Label)
	}
}

func TestParseProtonNumberChoice(t *testing.T) {
	servers := testProtonServers(t)
	choices := protonLocationChoices(servers)
	if got, err := parseProtonNumberChoice("0", servers); err != nil || got != "any" {
		t.Fatalf("choice 0 = %q, %v", got, err)
	}
	if got, err := parseProtonNumberChoice("1", servers); err != nil || got != choices[1].Code {
		t.Fatalf("choice 1 = %q, %v; want %q", got, err, choices[1].Code)
	}
	if got, err := parseProtonNumberChoice("us/san-jose", servers); err != nil || got != "us/san-jose" {
		t.Fatalf("choice us/san-jose = %q, %v", got, err)
	}
	if _, err := parseProtonNumberChoice("999", servers); err == nil {
		t.Fatal("expected out-of-range error")
	}
}

func TestBuildProtonConfig(t *testing.T) {
	servers := testProtonServers(t)
	server, err := selectProtonServer(servers, "us/san-jose")
	if err != nil {
		t.Fatal(err)
	}

	config := buildConfig(configOptions{
		Backend:          backendProton,
		Country:          "us/san-jose",
		ListenPort:       10820,
		TUN:              true,
		InterfaceName:    "sb-proton",
		ProtonPrivateKey: testProtonKey,
		ProtonServer:     &server,
		ProtonEndpoint:   "1.2.3.4",
		ProtonAddress:    "10.2.0.2/32",
		ProtonDNS:        "10.2.0.1",
		ProtonMTU:        1420,
	})

	if len(config.Inbounds) != 2 || config.Inbounds[0].Type != "tun" || config.Inbounds[0].InterfaceName != "sb-proton" {
		t.Fatalf("unexpected inbounds: %+v", config.Inbounds)
	}
	if len(config.Endpoints) != 1 {
		t.Fatalf("endpoints = %d, want 1", len(config.Endpoints))
	}
	endpoint := config.Endpoints[0]
	if endpoint.Type != "wireguard" || endpoint.Tag != "proton-out" {
		t.Fatalf("unexpected endpoint: %+v", endpoint)
	}
	if endpoint.PrivateKey != testProtonKey {
		t.Fatalf("private key = %q", endpoint.PrivateKey)
	}
	if len(endpoint.Address) != 1 || endpoint.Address[0] != "10.2.0.2/32" {
		t.Fatalf("addresses = %+v", endpoint.Address)
	}
	if endpoint.MTU != 1420 {
		t.Fatalf("MTU = %d, want 1420", endpoint.MTU)
	}
	if len(endpoint.Peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(endpoint.Peers))
	}
	peer := endpoint.Peers[0]
	if peer.Address != "1.2.3.4" || peer.Port != protonEndpointPort {
		t.Fatalf("unexpected peer: %+v", peer)
	}
	if peer.PublicKey != server.WGPubKey {
		t.Fatalf("peer public key = %q", peer.PublicKey)
	}
	if len(peer.AllowedIPs) != 2 || peer.AllowedIPs[0] != "0.0.0.0/0" || peer.AllowedIPs[1] != "::/0" {
		t.Fatalf("allowed IPs = %+v", peer.AllowedIPs)
	}
	if peer.PersistentKeepaliveInterval != 25 {
		t.Fatalf("keepalive = %d, want 25", peer.PersistentKeepaliveInterval)
	}

	if len(config.DNS.Servers) != 1 || config.DNS.Servers[0].Server != "10.2.0.1" || config.DNS.Servers[0].Detour != "proton-out" {
		t.Fatalf("unexpected DNS: %+v", config.DNS.Servers)
	}
	last := config.Route.Rules[len(config.Route.Rules)-1]
	if last.Outbound != "proton-out" {
		t.Fatalf("last route rule = %+v, want proton-out", last)
	}
	for _, rule := range config.Route.Rules {
		if rule.Network == "udp" && rule.Action == "reject" {
			t.Fatal("Proton supports UDP and should not reject it")
		}
	}
}

func TestBuildProtonConfigProxyOnly(t *testing.T) {
	server := protonServer{
		Country:    "United States",
		City:       "San Jose",
		ServerName: "US-FREE#1",
		WGPubKey:   testProtonKey,
		Free:       true,
		IPs:        []string{"1.2.3.4"},
	}
	config := buildConfig(configOptions{
		Backend:          backendProton,
		ListenPort:       10821,
		ProtonPrivateKey: testProtonKey,
		ProtonServer:     &server,
	})

	if len(config.Inbounds) != 1 || config.Inbounds[0].Type != "mixed" {
		t.Fatalf("unexpected inbounds: %+v", config.Inbounds)
	}
	if config.Endpoints[0].Address[0] != protonDefaultAddress {
		t.Fatalf("default address = %q", config.Endpoints[0].Address[0])
	}
	if config.Endpoints[0].MTU != protonDefaultMTU {
		t.Fatalf("default MTU = %d", config.Endpoints[0].MTU)
	}
	if config.DNS.Servers[0].Server != protonDefaultDNS {
		t.Fatalf("default DNS = %q", config.DNS.Servers[0].Server)
	}
}

func TestProtonPrivateKey(t *testing.T) {
	keyBytes := make([]byte, 32)
	for i := range keyBytes {
		keyBytes[i] = byte(i + 1)
	}
	key := base64.StdEncoding.EncodeToString(keyBytes)

	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("# comment\nWG="+key+"\nOTHER=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WG", "")
	t.Setenv("ROUTER_ENV_FILE", envPath)
	got, err := protonPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if got != key {
		t.Fatalf("private key = %q, want the .env key", got)
	}

	t.Setenv("WG", key)
	got, err = protonPrivateKey()
	if err != nil || got != key {
		t.Fatalf("environment key = %q, %v", got, err)
	}

	if err := os.WriteFile(envPath, []byte("WG=not-a-valid-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("WG", "")
	if _, err := protonPrivateKey(); err == nil {
		t.Fatal("expected an error for an invalid private key")
	} else if strings.Contains(err.Error(), "not-a-valid-key") {
		t.Fatalf("error leaked the private key: %v", err)
	}

	if err := os.WriteFile(envPath, []byte("OTHER=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := protonPrivateKey(); err == nil {
		t.Fatal("expected an error for a missing WG key")
	}
}

func TestProtonConfigSettings(t *testing.T) {
	t.Setenv("ROUTER_ENV_FILE", filepath.Join(t.TempDir(), "missing.env"))
	t.Setenv("ROUTER_PROTON_ADDRESS", "")
	t.Setenv("ROUTER_PROTON_DNS", "")
	t.Setenv("ROUTER_PROTON_MTU", "")
	address, dns, mtu, err := protonConfigSettings()
	if err != nil {
		t.Fatal(err)
	}
	if address != protonDefaultAddress || dns != protonDefaultDNS || mtu != protonDefaultMTU {
		t.Fatalf("defaults = %q, %q, %d", address, dns, mtu)
	}

	t.Setenv("ROUTER_PROTON_ADDRESS", "10.2.0.3")
	t.Setenv("ROUTER_PROTON_DNS", "1.1.1.1")
	t.Setenv("ROUTER_PROTON_MTU", "1380")
	address, dns, mtu, err = protonConfigSettings()
	if err != nil {
		t.Fatal(err)
	}
	if address != "10.2.0.3/32" || dns != "1.1.1.1" || mtu != 1380 {
		t.Fatalf("overrides = %q, %q, %d", address, dns, mtu)
	}

	t.Setenv("ROUTER_PROTON_MTU", "9000")
	if _, _, _, err := protonConfigSettings(); err == nil {
		t.Fatal("expected an invalid MTU error")
	}
}
