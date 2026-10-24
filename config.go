package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type singBoxConfig struct {
	Log       singBoxLog        `json:"log"`
	DNS       singBoxDNS        `json:"dns"`
	Inbounds  []singBoxInbound  `json:"inbounds"`
	Endpoints []singBoxEndpoint `json:"endpoints,omitempty"`
	Outbounds []singBoxOutbound `json:"outbounds"`
	Route     singBoxRoute      `json:"route"`
}

type singBoxLog struct {
	Level     string `json:"level"`
	Timestamp bool   `json:"timestamp"`
	Output    string `json:"output,omitempty"`
}

type singBoxDNS struct {
	Servers []singBoxDNSServer `json:"servers"`
}

type singBoxDNSServer struct {
	Tag    string `json:"tag"`
	Type   string `json:"type"`
	Server string `json:"server"`
	Detour string `json:"detour,omitempty"`
}

type singBoxInbound struct {
	Type          string   `json:"type"`
	Tag           string   `json:"tag"`
	InterfaceName string   `json:"interface_name,omitempty"`
	Address       []string `json:"address,omitempty"`
	AutoRoute     bool     `json:"auto_route,omitempty"`
	StrictRoute   bool     `json:"strict_route,omitempty"`
	Stack         string   `json:"stack,omitempty"`
	Listen        string   `json:"listen,omitempty"`
	ListenPort    int      `json:"listen_port,omitempty"`
}

type singBoxEndpoint struct {
	Type       string        `json:"type"`
	Tag        string        `json:"tag"`
	Detour     string        `json:"detour,omitempty"`
	PrivateKey string        `json:"private_key"`
	Address    []string      `json:"address"`
	MTU        int           `json:"mtu,omitempty"`
	Peers      []singBoxPeer `json:"peers"`
}

type singBoxPeer struct {
	Address                     string   `json:"address"`
	Port                        int      `json:"port"`
	PublicKey                   string   `json:"public_key"`
	AllowedIPs                  []string `json:"allowed_ips"`
	PersistentKeepaliveInterval int      `json:"persistent_keepalive_interval,omitempty"`
}

type singBoxOutbound struct {
	Type           string            `json:"type"`
	Tag            string            `json:"tag"`
	ExecutablePath string            `json:"executable_path,omitempty"`
	DataDirectory  string            `json:"data_directory,omitempty"`
	ExtraArgs      []string          `json:"extra_args,omitempty"`
	Torrc          map[string]string `json:"torrc,omitempty"`
}

type singBoxRoute struct {
	AutoDetectInterface bool          `json:"auto_detect_interface"`
	Rules               []singBoxRule `json:"rules"`
}

type singBoxRule struct {
	Port        int    `json:"port,omitempty"`
	Protocol    string `json:"protocol,omitempty"`
	IPIsPrivate bool   `json:"ip_is_private,omitempty"`
	Network     string `json:"network,omitempty"`
	Action      string `json:"action,omitempty"`
	Outbound    string `json:"outbound,omitempty"`
}

type configOptions struct {
	Backend           string
	Country           string
	ListenPort        int
	TUN               bool
	InterfaceName     string
	TorBinary         string
	TorDataDir        string
	GeoIP             string
	GeoIP6            string
	LogPath           string
	WarpAccount       *warpAccount
	WarpEndpoint      string
	WarpInner         *warpAccount
	WarpInnerEndpoint string
	ProtonPrivateKey  string
	ProtonServer      *protonServer
	ProtonEndpoint    string
	ProtonAddress     string
	ProtonDNS         string
	ProtonMTU         int
}

const (
	warpOuterMTU = 1280
	warpInnerMTU = 1200
)

func buildConfig(opts configOptions) singBoxConfig {
	switch opts.Backend {
	case backendWarp:
		return buildWarpConfig(opts)
	case backendProton:
		return buildProtonConfig(opts)
	default:
		return buildTorConfig(opts)
	}
}

func buildTorConfig(opts configOptions) singBoxConfig {
	dns := singBoxDNS{
		Servers: []singBoxDNSServer{{Tag: "dns-remote", Type: "udp", Server: "1.1.1.1"}},
	}
	if opts.TUN {
		dns.Servers = []singBoxDNSServer{{Tag: "dns-tor", Type: "tcp", Server: "1.1.1.1", Detour: "tor-out"}}
	}

	inbounds := []singBoxInbound{{
		Type:       "mixed",
		Tag:        "mixed-in",
		Listen:     "127.0.0.1",
		ListenPort: opts.ListenPort,
	}}
	if opts.TUN {
		inbounds = append([]singBoxInbound{{
			Type:          "tun",
			Tag:           "tun-in",
			InterfaceName: opts.InterfaceName,
			Address:       []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			AutoRoute:     true,
			StrictRoute:   true,
			Stack:         "gvisor",
		}}, inbounds...)
	}

	torrc := map[string]string{"ClientOnly": "1"}
	if opts.Country != "any" {
		torrc["ExitNodes"] = "{" + opts.Country + "}"
		torrc["StrictNodes"] = "1"
	}

	var extraArgs []string
	if opts.GeoIP != "" {
		extraArgs = append(extraArgs, "--GeoIPFile", opts.GeoIP)
	}
	if opts.GeoIP6 != "" {
		extraArgs = append(extraArgs, "--GeoIPv6File", opts.GeoIP6)
	}

	outbounds := []singBoxOutbound{
		{
			Type:           "tor",
			Tag:            "tor-out",
			ExecutablePath: opts.TorBinary,
			DataDirectory:  opts.TorDataDir,
			ExtraArgs:      extraArgs,
			Torrc:          torrc,
		},
		{Type: "direct", Tag: "direct"},
		{Type: "block", Tag: "block"},
	}

	rules := []singBoxRule{
		{Port: 53, Action: "hijack-dns"},
		{Protocol: "dns", Action: "hijack-dns"},
		{IPIsPrivate: true, Outbound: "direct"},
	}
	if opts.TUN {
		// Tor is TCP-only. Reject UDP so apps fall back to TCP instead of leaking.
		rules = append(rules, singBoxRule{Network: "udp", Action: "reject"})
	}
	rules = append(rules, singBoxRule{Outbound: "tor-out"})

	return singBoxConfig{
		Log:       singBoxLog{Level: "info", Timestamp: true, Output: opts.LogPath},
		DNS:       dns,
		Inbounds:  inbounds,
		Outbounds: outbounds,
		Route: singBoxRoute{
			AutoDetectInterface: true,
			Rules:               rules,
		},
	}
}

func buildWarpConfig(opts configOptions) singBoxConfig {
	dns := singBoxDNS{
		Servers: []singBoxDNSServer{{Tag: "dns-remote", Type: "udp", Server: "1.1.1.1"}},
	}

	inbounds := []singBoxInbound{{
		Type:       "mixed",
		Tag:        "mixed-in",
		Listen:     "127.0.0.1",
		ListenPort: opts.ListenPort,
	}}
	if opts.TUN {
		inbounds = append([]singBoxInbound{{
			Type:          "tun",
			Tag:           "tun-in",
			InterfaceName: opts.InterfaceName,
			Address:       []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			AutoRoute:     true,
			StrictRoute:   false,
			Stack:         "mixed",
		}}, inbounds...)
	}

	endpoints := []singBoxEndpoint{{
		Type:       "wireguard",
		Tag:        "warp-outer",
		PrivateKey: warpAccountKey(opts.WarpAccount),
		Address:    warpAddresses(opts.WarpAccount),
		MTU:        warpOuterMTU,
		Peers: []singBoxPeer{{
			Address:    opts.WarpEndpoint,
			Port:       warpEndpointPort,
			PublicKey:  warpPeerKey(opts.WarpAccount),
			AllowedIPs: []string{"0.0.0.0/0", "::/0"},
		}},
	}}

	target := "warp-outer"
	if opts.WarpInner != nil && opts.WarpInnerEndpoint != "" {
		endpoints = append(endpoints, singBoxEndpoint{
			Type:       "wireguard",
			Tag:        "warp-inner",
			Detour:     "warp-outer",
			PrivateKey: warpAccountKey(opts.WarpInner),
			Address:    warpAddresses(opts.WarpInner),
			MTU:        warpInnerMTU,
			Peers: []singBoxPeer{{
				Address:    opts.WarpInnerEndpoint,
				Port:       warpEndpointPort,
				PublicKey:  warpPeerKey(opts.WarpInner),
				AllowedIPs: []string{"0.0.0.0/0", "::/0"},
			}},
		})
		target = "warp-inner"
	}

	outbounds := []singBoxOutbound{
		{Type: "direct", Tag: "direct"},
		{Type: "block", Tag: "block"},
	}

	rules := []singBoxRule{
		{Port: 53, Action: "hijack-dns"},
		{Protocol: "dns", Action: "hijack-dns"},
		{IPIsPrivate: true, Outbound: "direct"},
		{Outbound: target},
	}

	return singBoxConfig{
		Log:       singBoxLog{Level: "info", Timestamp: true, Output: opts.LogPath},
		DNS:       dns,
		Inbounds:  inbounds,
		Endpoints: endpoints,
		Outbounds: outbounds,
		Route: singBoxRoute{
			AutoDetectInterface: true,
			Rules:               rules,
		},
	}
}

func buildProtonConfig(opts configOptions) singBoxConfig {
	address := opts.ProtonAddress
	if address == "" {
		address = protonDefaultAddress
	}
	dnsServer := opts.ProtonDNS
	if dnsServer == "" {
		dnsServer = protonDefaultDNS
	}
	mtu := opts.ProtonMTU
	if mtu == 0 {
		mtu = protonDefaultMTU
	}

	endpointAddress := opts.ProtonEndpoint
	publicKey := ""
	if opts.ProtonServer != nil {
		publicKey = opts.ProtonServer.WGPubKey
		if endpointAddress == "" {
			endpointAddress, _ = opts.ProtonServer.endpoint()
		}
	}

	dns := singBoxDNS{
		Servers: []singBoxDNSServer{{
			Tag:    "dns-proton",
			Type:   "udp",
			Server: dnsServer,
			Detour: "proton-out",
		}},
	}

	inbounds := []singBoxInbound{{
		Type:       "mixed",
		Tag:        "mixed-in",
		Listen:     "127.0.0.1",
		ListenPort: opts.ListenPort,
	}}
	if opts.TUN {
		inbounds = append([]singBoxInbound{{
			Type:          "tun",
			Tag:           "tun-in",
			InterfaceName: opts.InterfaceName,
			Address:       []string{"172.19.0.1/30", "fdfe:dcba:9876::1/126"},
			AutoRoute:     true,
			StrictRoute:   false,
			Stack:         "mixed",
		}}, inbounds...)
	}

	endpoints := []singBoxEndpoint{{
		Type:       "wireguard",
		Tag:        "proton-out",
		PrivateKey: opts.ProtonPrivateKey,
		Address:    []string{address},
		MTU:        mtu,
		Peers: []singBoxPeer{{
			Address:                     endpointAddress,
			Port:                        protonEndpointPort,
			PublicKey:                   publicKey,
			AllowedIPs:                  []string{"0.0.0.0/0", "::/0"},
			PersistentKeepaliveInterval: 25,
		}},
	}}

	outbounds := []singBoxOutbound{
		{Type: "direct", Tag: "direct"},
		{Type: "block", Tag: "block"},
	}

	rules := []singBoxRule{
		{Port: 53, Action: "hijack-dns"},
		{Protocol: "dns", Action: "hijack-dns"},
		{IPIsPrivate: true, Outbound: "direct"},
		{Outbound: "proton-out"},
	}

	return singBoxConfig{
		Log:       singBoxLog{Level: "info", Timestamp: true, Output: opts.LogPath},
		DNS:       dns,
		Inbounds:  inbounds,
		Endpoints: endpoints,
		Outbounds: outbounds,
		Route: singBoxRoute{
			AutoDetectInterface: true,
			Rules:               rules,
		},
	}
}

func warpAddresses(account *warpAccount) []string {
	if account == nil {
		return nil
	}
	var addresses []string
	if account.V4Address != "" {
		addresses = append(addresses, account.V4Address+"/32")
	}
	if account.V6Address != "" {
		addresses = append(addresses, account.V6Address+"/128")
	}
	return addresses
}

func warpAccountKey(account *warpAccount) string {
	if account == nil {
		return ""
	}
	return account.PrivateKey
}

func warpPeerKey(account *warpAccount) string {
	if account == nil {
		return ""
	}
	return account.PeerPublicKey
}

func writeConfig(path string, config singBoxConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("encode sing-box config: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("write sing-box config: %w", err)
	}
	return nil
}
