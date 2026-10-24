package main

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildConfigTUN(t *testing.T) {
	config := buildConfig(configOptions{
		Country:       "jp",
		ListenPort:    10808,
		TUN:           true,
		InterfaceName: "sb-tor",
		TorBinary:     "/usr/bin/tor",
		TorDataDir:    "/tmp/tor",
		GeoIP:         "/usr/share/tor/geoip",
	})

	if len(config.Inbounds) != 2 {
		t.Fatalf("inbounds = %d, want 2", len(config.Inbounds))
	}
	if config.Inbounds[0].Type != "tun" || config.Inbounds[0].InterfaceName != "sb-tor" {
		t.Fatalf("unexpected TUN inbound: %+v", config.Inbounds[0])
	}
	if config.Inbounds[1].Type != "mixed" || config.Inbounds[1].ListenPort != 10808 {
		t.Fatalf("unexpected mixed inbound: %+v", config.Inbounds[1])
	}
	if got := config.Outbounds[0].Torrc["ExitNodes"]; got != "{jp}" {
		t.Fatalf("ExitNodes = %q, want {jp}", got)
	}
	if len(config.DNS.Servers) != 1 || config.DNS.Servers[0].Detour != "tor-out" {
		t.Fatalf("unexpected DNS servers: %+v", config.DNS.Servers)
	}
	last := config.Route.Rules[len(config.Route.Rules)-1]
	if last.Outbound != "tor-out" {
		t.Fatalf("last route rule = %+v, want tor-out", last)
	}
	if len(config.Endpoints) != 0 {
		t.Fatalf("Tor config should not have endpoints: %+v", config.Endpoints)
	}
}

func TestBuildConfigProxyOnly(t *testing.T) {
	config := buildConfig(configOptions{
		Country:    "any",
		ListenPort: 10809,
		TUN:        false,
		TorBinary:  "/usr/bin/tor",
		TorDataDir: "/tmp/tor",
	})

	if len(config.Inbounds) != 1 || config.Inbounds[0].Type != "mixed" {
		t.Fatalf("unexpected inbounds: %+v", config.Inbounds)
	}
	if config.DNS.Servers[0].Type != "udp" {
		t.Fatalf("proxy mode DNS type = %q, want udp", config.DNS.Servers[0].Type)
	}
	if _, ok := config.Outbounds[0].Torrc["ExitNodes"]; ok {
		t.Fatal("ExitNodes should not be set for any")
	}
	for _, rule := range config.Route.Rules {
		if rule.Network == "udp" && rule.Action == "reject" {
			t.Fatal("proxy mode should not reject UDP")
		}
	}
}

func TestBuildWarpConfigTUN(t *testing.T) {
	account := &warpAccount{
		PrivateKey:    "CG525hUWlBjiFT3ae10/ExXT3k+KXFHidf5FFx99K1I=",
		PeerPublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		V4Address:     "172.16.0.2",
		V6Address:     "2606:4700:110:8623:a9df:c1c8:25e8:3b9c",
	}
	config := buildConfig(configOptions{
		Backend:       backendWarp,
		Country:       "any",
		ListenPort:    10810,
		TUN:           true,
		InterfaceName: "sb-warp",
		WarpAccount:   account,
		WarpEndpoint:  "162.159.192.1",
	})

	if len(config.Endpoints) != 1 {
		t.Fatalf("endpoints = %d, want 1", len(config.Endpoints))
	}
	endpoint := config.Endpoints[0]
	if endpoint.Type != "wireguard" || endpoint.Tag != "warp-outer" {
		t.Fatalf("unexpected endpoint: %+v", endpoint)
	}
	if endpoint.PrivateKey != account.PrivateKey {
		t.Fatalf("private key = %q", endpoint.PrivateKey)
	}
	if endpoint.Detour != "" || endpoint.MTU != warpOuterMTU {
		t.Fatalf("unexpected outer endpoint options: %+v", endpoint)
	}
	if len(endpoint.Address) != 2 || endpoint.Address[0] != "172.16.0.2/32" || endpoint.Address[1] != account.V6Address+"/128" {
		t.Fatalf("unexpected addresses: %+v", endpoint.Address)
	}
	if len(endpoint.Peers) != 1 {
		t.Fatalf("peers = %d, want 1", len(endpoint.Peers))
	}
	peer := endpoint.Peers[0]
	if peer.Address != "162.159.192.1" || peer.Port != 2408 || peer.PublicKey != account.PeerPublicKey {
		t.Fatalf("unexpected peer: %+v", peer)
	}
	if len(config.Inbounds) != 2 || config.Inbounds[0].Type != "tun" || config.Inbounds[0].InterfaceName != "sb-warp" {
		t.Fatalf("unexpected inbounds: %+v", config.Inbounds)
	}
	if config.Inbounds[0].Stack != "mixed" || config.Inbounds[0].StrictRoute {
		t.Fatalf("unexpected WARP TUN options: %+v", config.Inbounds[0])
	}
	last := config.Route.Rules[len(config.Route.Rules)-1]
	if last.Outbound != "warp-outer" {
		t.Fatalf("last route rule = %+v, want warp-outer", last)
	}
	for _, rule := range config.Route.Rules {
		if rule.Network == "udp" && rule.Action == "reject" {
			t.Fatal("WARP supports UDP and should not reject it")
		}
	}
}

func TestBuildWarpConfigProxyOnly(t *testing.T) {
	account := &warpAccount{
		PrivateKey:    "CG525hUWlBjiFT3ae10/ExXT3k+KXFHidf5FFx99K1I=",
		PeerPublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		V4Address:     "172.16.0.2",
	}
	config := buildConfig(configOptions{
		Backend:      backendWarp,
		Country:      "any",
		ListenPort:   10811,
		WarpAccount:  account,
		WarpEndpoint: "162.159.192.1",
	})

	if len(config.Inbounds) != 1 || config.Inbounds[0].Type != "mixed" {
		t.Fatalf("unexpected inbounds: %+v", config.Inbounds)
	}
	if len(config.Endpoints) != 1 || len(config.Endpoints[0].Address) != 1 {
		t.Fatalf("unexpected endpoints: %+v", config.Endpoints)
	}
	if config.Endpoints[0].MTU != warpOuterMTU || config.Endpoints[0].Detour != "" {
		t.Fatalf("unexpected outer endpoint options: %+v", config.Endpoints[0])
	}
	if config.DNS.Servers[0].Detour != "" {
		t.Fatalf("WARP DNS should use the default route: %+v", config.DNS.Servers[0])
	}
	last := config.Route.Rules[len(config.Route.Rules)-1]
	if last.Outbound != "warp-outer" {
		t.Fatalf("last route rule = %+v, want warp-outer", last)
	}
}

func TestBuildWarpConfigDoubleWarp(t *testing.T) {
	outer := &warpAccount{
		PrivateKey:    "CG525hUWlBjiFT3ae10/ExXT3k+KXFHidf5FFx99K1I=",
		PeerPublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		V4Address:     "172.16.0.2",
		V6Address:     "2606:4700:110:8623:a9df:c1c8:25e8:3b9c",
	}
	inner := &warpAccount{
		PrivateKey:    "6KUqPQEfYPSn+I0DWhFHB/PNOwo8L2i8FrxJMiEknHA=",
		PeerPublicKey: "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		V4Address:     "172.16.0.2",
		V6Address:     "2606:4700:110:8d92:2f48:1985:c3f2:80f6",
	}
	config := buildConfig(configOptions{
		Backend:           backendWarp,
		Country:           "us",
		ListenPort:        10812,
		WarpAccount:       outer,
		WarpEndpoint:      "162.159.192.3",
		WarpInner:         inner,
		WarpInnerEndpoint: "2602:fc59:b0:64::a29f:c006",
	})

	if len(config.Endpoints) != 2 {
		t.Fatalf("endpoints = %d, want 2", len(config.Endpoints))
	}

	outerEndpoint := config.Endpoints[0]
	if outerEndpoint.Tag != "warp-outer" || outerEndpoint.Detour != "" || outerEndpoint.MTU != warpOuterMTU {
		t.Fatalf("unexpected outer endpoint: %+v", outerEndpoint)
	}
	if len(outerEndpoint.Peers) != 1 || outerEndpoint.Peers[0].Address != "162.159.192.3" {
		t.Fatalf("unexpected outer peer: %+v", outerEndpoint.Peers)
	}

	innerEndpoint := config.Endpoints[1]
	if innerEndpoint.Tag != "warp-inner" || innerEndpoint.Detour != "warp-outer" || innerEndpoint.MTU != warpInnerMTU {
		t.Fatalf("unexpected inner endpoint: %+v", innerEndpoint)
	}
	if innerEndpoint.PrivateKey != inner.PrivateKey {
		t.Fatalf("inner private key = %q", innerEndpoint.PrivateKey)
	}
	if len(innerEndpoint.Peers) != 1 {
		t.Fatalf("inner peers = %d, want 1", len(innerEndpoint.Peers))
	}
	innerPeer := innerEndpoint.Peers[0]
	if innerPeer.Address != "2602:fc59:b0:64::a29f:c006" || innerPeer.Port != 2408 || innerPeer.PublicKey != inner.PeerPublicKey {
		t.Fatalf("unexpected inner peer: %+v", innerPeer)
	}

	last := config.Route.Rules[len(config.Route.Rules)-1]
	if last.Outbound != "warp-inner" {
		t.Fatalf("last route rule = %+v, want warp-inner", last)
	}
}

func TestWarpPeerEndpoint(t *testing.T) {
	account := &warpAccount{PeerEndpointV4: "162.159.192.1"}
	tests := []struct {
		country string
		want    string
		wantErr bool
	}{
		{"any", "162.159.192.1", false},
		{"us", "2602:fc59:b0:64::a29f:c001", false},
		{"nl", "", true},
		{"de", "", true},
		{"fi", "", true},
		{"jp", "", true},
	}
	for _, test := range tests {
		got, err := warpPeerEndpoint(test.country, account)
		if (err != nil) != test.wantErr {
			t.Errorf("warpPeerEndpoint(%q) error = %v, wantErr %v", test.country, err, test.wantErr)
			continue
		}
		if !test.wantErr && got != test.want {
			t.Errorf("warpPeerEndpoint(%q) = %q, want %q", test.country, got, test.want)
		}
	}
}

func TestWarpPeerEndpointUS(t *testing.T) {
	account := &warpAccount{PeerEndpointV4: "162.159.192.1"}
	for i := 0; i < 20; i++ {
		got, err := warpPeerEndpoint("us", account)
		if err != nil {
			t.Fatal(err)
		}
		if got != "2602:fc59:b0:64::a29f:c001" {
			t.Fatalf("warpPeerEndpoint(us) = %q, want the Fremont NAT64 address", got)
		}
	}
}

func TestWarpUSPrefixLockedToFremont(t *testing.T) {
	prefixes := warpNAT64Prefixes["us"]
	if len(prefixes) != 1 || prefixes[0] != "2602:fc59:b0:64::/96" {
		t.Fatalf("US NAT64 prefixes = %v, want only Fremont", prefixes)
	}
}

func TestWarpCountryPrefixes(t *testing.T) {
	if len(warpNAT64Prefixes) != len(warpCountryCodes) {
		t.Fatalf("%d WARP countries but %d prefix sets", len(warpCountryCodes), len(warpNAT64Prefixes))
	}
	for _, code := range warpCountryCodes {
		prefixes := warpNAT64Prefixes[code]
		if len(prefixes) == 0 {
			t.Errorf("WARP country %q has no NAT64 prefix", code)
		}
		for _, value := range prefixes {
			prefix, err := netip.ParsePrefix(value)
			if err != nil {
				t.Errorf("WARP country %q: %v", code, err)
				continue
			}
			if prefix.Bits() != 96 {
				t.Errorf("WARP country %q prefix %q is not /96", code, value)
			}
		}
	}
}

func TestGenerateWireGuardKeypair(t *testing.T) {
	privateKey, publicKey, err := generateWireGuardKeypair()
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, err := base64.StdEncoding.DecodeString(privateKey)
	if err != nil || len(privateBytes) != 32 {
		t.Fatalf("bad private key %q: %v", privateKey, err)
	}
	publicBytes, err := base64.StdEncoding.DecodeString(publicKey)
	if err != nil || len(publicBytes) != 32 {
		t.Fatalf("bad public key %q: %v", publicKey, err)
	}
	key, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		t.Fatal(err)
	}
	if got := base64.StdEncoding.EncodeToString(key.PublicKey().Bytes()); got != publicKey {
		t.Fatalf("public key = %q, want %q", publicKey, got)
	}
}

func TestWarpInnerAccountPath(t *testing.T) {
	t.Setenv("ROUTER_WARP_INNER_ACCOUNT", "/tmp/custom-inner.json")
	if got := warpInnerAccountPath(); got != "/tmp/custom-inner.json" {
		t.Fatalf("warpInnerAccountPath() = %q", got)
	}
}

func TestWarpAccountCache(t *testing.T) {
	path := filepath.Join(t.TempDir(), "warp_account.json")
	account := &warpAccount{
		PrivateKey:     "CG525hUWlBjiFT3ae10/ExXT3k+KXFHidf5FFx99K1I=",
		PeerPublicKey:  "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
		PeerEndpointV4: "162.159.192.1",
		V4Address:      "172.16.0.2",
	}
	if err := saveWarpAccount(path, account); err != nil {
		t.Fatal(err)
	}
	loaded, err := loadWarpAccount(path)
	if err != nil {
		t.Fatal(err)
	}
	if !loaded.valid() {
		t.Fatalf("loaded account is invalid: %+v", loaded)
	}
	if loaded.PrivateKey != account.PrivateKey || loaded.PeerPublicKey != account.PeerPublicKey {
		t.Fatalf("loaded account = %+v", loaded)
	}
}

func TestWarpAccountFromRegistration(t *testing.T) {
	const payload = `{
		"id": "test-device",
		"config": {
			"interface": {
				"addresses": {
					"v4": "172.16.0.2",
					"v6": "2606:4700:110:8623:a9df:c1c8:25e8:3b9c"
				}
			},
			"peers": [{
				"public_key": "bmXOC+F1FxEMF9dyiK2H5/1SUtzH0JuVo51h2wPfgyo=",
				"endpoint": {
					"v4": "162.159.192.10:0",
					"v6": "[2606:4700:d0::a29f:c00a]:0"
				}
			}]
		}
	}`
	var registration warpRegistrationResponse
	if err := json.Unmarshal([]byte(payload), &registration); err != nil {
		t.Fatal(err)
	}
	account, err := warpAccountFromRegistration(
		&registration,
		"CG525hUWlBjiFT3ae10/ExXT3k+KXFHidf5FFx99K1I=",
		"6B6vzQf6xjc8G5Cw7Q1GxRcjt4D4U8rWiXSk4XaJ4mw=",
	)
	if err != nil {
		t.Fatal(err)
	}
	if account.ID != "test-device" || account.PeerEndpointV4 != "162.159.192.10" ||
		account.PeerEndpointV6 != "2606:4700:d0::a29f:c00a" {
		t.Fatalf("unexpected account: %+v", account)
	}
	if account.V4Address != "172.16.0.2" || account.V6Address != "2606:4700:110:8623:a9df:c1c8:25e8:3b9c" {
		t.Fatalf("unexpected addresses: %+v", account)
	}

	if _, err := warpAccountFromRegistration(&warpRegistrationResponse{}, "unused", "unused"); err == nil {
		t.Fatal("expected error for a registration without peers")
	}
}

func TestParseFlagsBackend(t *testing.T) {
	opts, err := parseFlags([]string{"-b", "warp", "-c", "us"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.backend != backendWarp || opts.interfaceName != defaultWarpInterface || opts.country != "us" {
		t.Fatalf("unexpected options: %+v", opts)
	}

	opts, err = parseFlags(nil)
	if err != nil {
		t.Fatal(err)
	}
	if opts.backend != backendWarp || opts.interfaceName != defaultWarpInterface {
		t.Fatalf("unexpected defaults: %+v", opts)
	}

	opts, err = parseFlags([]string{"-b", "tor"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.backend != backendTor || opts.interfaceName != defaultTorInterface {
		t.Fatalf("unexpected Tor options: %+v", opts)
	}

	opts, err = parseFlags([]string{"-b", "proton", "-c", "us/san-jose"})
	if err != nil {
		t.Fatal(err)
	}
	if opts.backend != backendProton || opts.interfaceName != defaultProtonInterface || opts.country != "us/san-jose" {
		t.Fatalf("unexpected Proton options: %+v", opts)
	}

	if _, err := parseFlags([]string{"-b", "nope"}); err == nil {
		t.Fatal("expected invalid backend error")
	}
}

func TestResolveCountry(t *testing.T) {
	tests := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"", "any", false},
		{"ANY", "any", false},
		{"de", "de", false},
		{"JP", "jp", false},
		{"germany", "", true},
		{"d3", "", true},
	}
	for _, test := range tests {
		got, err := resolveCountry(test.in)
		if (err != nil) != test.wantErr {
			t.Errorf("resolveCountry(%q) error = %v, wantErr %v", test.in, err, test.wantErr)
			continue
		}
		if !test.wantErr && got != test.want {
			t.Errorf("resolveCountry(%q) = %q, want %q", test.in, got, test.want)
		}
	}

	got, err := resolveCountry("random")
	if err != nil {
		t.Fatalf("resolveCountry(random) error = %v", err)
	}
	found := false
	for _, c := range commonCountries {
		if c.Code == got {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("resolveCountry(random) = %q, not a common country", got)
	}
}

func TestResolveWarpCountry(t *testing.T) {
	got, err := resolveCountryForBackend(backendWarp, "us")
	if err != nil || got != "us" {
		t.Fatalf("resolveCountryForBackend(warp, us) = %q, %v", got, err)
	}
	if _, err := resolveCountryForBackend(backendWarp, "jp"); err == nil {
		t.Fatal("expected WARP country jp to be rejected")
	}
	got, err = resolveCountryForBackend(backendWarp, "random")
	if err != nil || got != "us" {
		t.Fatalf("WARP random country = %q, %v", got, err)
	}
}

func TestResolveWarpCountryBlocked(t *testing.T) {
	for _, code := range []string{"de", "fi", "nl"} {
		_, err := resolveCountryForBackend(backendWarp, code)
		if err == nil {
			t.Fatalf("expected WARP country %q to be rejected", code)
		}
		message := err.Error()
		if !strings.Contains(message, "block Cloudflare WARP egress") {
			t.Errorf("WARP country %q error = %q, want blocked-NAT64 explanation", code, message)
		}
		if !strings.Contains(message, "-b tor") {
			t.Errorf("WARP country %q error = %q, want Tor suggestion", code, message)
		}
	}
}

func TestNextCountry(t *testing.T) {
	if got := nextCountry("any"); got != commonCountries[0].Code {
		t.Fatalf("nextCountry(any) = %q", got)
	}
	if got := nextCountry(commonCountries[0].Code); got != commonCountries[1].Code {
		t.Fatalf("nextCountry(first) = %q", got)
	}
	last := commonCountries[len(commonCountries)-1].Code
	if got := nextCountry(last); got != commonCountries[0].Code {
		t.Fatalf("nextCountry(last) = %q, want wrap", got)
	}

	if got := nextCountryForBackend(backendWarp, "any"); got != warpCountryCodes[0] {
		t.Fatalf("nextCountryForBackend(warp, any) = %q", got)
	}
	if got := nextCountryForBackend(backendWarp, warpCountryCodes[len(warpCountryCodes)-1]); got != warpCountryCodes[0] {
		t.Fatalf("nextCountryForBackend(warp, last) = %q, want wrap", got)
	}
}

func TestParseCountryChoice(t *testing.T) {
	if got, err := parseCountryChoice(backendTor, "0"); err != nil || got != "any" {
		t.Fatalf("choice 0 = %q, %v", got, err)
	}
	if got, err := parseCountryChoice(backendTor, "1"); err != nil || got != commonCountries[0].Code {
		t.Fatalf("choice 1 = %q, %v", got, err)
	}
	if _, err := parseCountryChoice(backendTor, "999"); err == nil {
		t.Fatal("expected out-of-range error")
	}
	if got, err := parseCountryChoice(backendWarp, "1"); err != nil || got != warpCountryCodes[0] {
		t.Fatalf("WARP choice 1 = %q, %v", got, err)
	}
	if _, err := parseCountryChoice(backendWarp, "jp"); err == nil {
		t.Fatal("expected unsupported WARP country error")
	}
}
