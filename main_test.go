package main

import "testing"

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
}

func TestParseCountryChoice(t *testing.T) {
	if got, err := parseCountryChoice("0"); err != nil || got != "any" {
		t.Fatalf("choice 0 = %q, %v", got, err)
	}
	if got, err := parseCountryChoice("1"); err != nil || got != commonCountries[0].Code {
		t.Fatalf("choice 1 = %q, %v", got, err)
	}
	if _, err := parseCountryChoice("999"); err == nil {
		t.Fatal("expected out-of-range error")
	}
}
