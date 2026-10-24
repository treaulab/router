package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	cryptorand "crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"time"
)

const (
	warpAPIURL       = "https://api.cloudflareclient.com/v0a2158/reg"
	warpEndpointPort = 2408
	warpDefaultHost  = "162.159.192.1"
)

// warpNAT64Prefixes maps WARP country codes to public NAT64 /96 prefixes.
// Only endpoints that have been verified to complete a WireGuard handshake
// through an outer WARP tunnel are listed. Public European gateways currently
// block Cloudflare WARP egress, so they are rejected before a tunnel starts.
var warpNAT64Prefixes = map[string][]string{
	"us": {"2602:fc59:b0:64::/96"}, // ZTVI, Fremont
}

type warpAccount struct {
	ID             string `json:"id,omitempty"`
	PrivateKey     string `json:"private_key"`
	PublicKey      string `json:"public_key,omitempty"`
	PeerPublicKey  string `json:"peer_public_key"`
	PeerEndpointV4 string `json:"peer_endpoint_v4,omitempty"`
	PeerEndpointV6 string `json:"peer_endpoint_v6,omitempty"`
	V4Address      string `json:"v4_address"`
	V6Address      string `json:"v6_address"`
}

type warpRegistrationResponse struct {
	ID     string `json:"id"`
	Config struct {
		Interface struct {
			Addresses struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"addresses"`
		} `json:"interface"`
		Peers []struct {
			PublicKey string `json:"public_key"`
			Endpoint  struct {
				V4 string `json:"v4"`
				V6 string `json:"v6"`
			} `json:"endpoint"`
		} `json:"peers"`
	} `json:"config"`
}

func warpAccountPath() string {
	if path := os.Getenv("ROUTER_WARP_ACCOUNT"); path != "" {
		return path
	}
	return "warp_account.json"
}

func warpInnerAccountPath() string {
	if path := os.Getenv("ROUTER_WARP_INNER_ACCOUNT"); path != "" {
		return path
	}
	return "warp_inner_account.json"
}

// loadOrRegisterWarpInner returns the inner Double WARP account, registering
// and caching one on first use.
func loadOrRegisterWarpInner(ctx context.Context) (*warpAccount, error) {
	fmt.Fprintln(stdout, "Initializing Double WARP inner account...")
	return loadOrRegisterWarp(ctx, warpInnerAccountPath())
}

func loadOrRegisterWarp(ctx context.Context, path string) (*warpAccount, error) {
	account, err := loadWarpAccount(path)
	if err == nil && account.valid() {
		fmt.Fprintln(stdout, "Using cached WARP account:", path)
		return account, nil
	}
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		fmt.Fprintf(stderr, "warning: ignoring invalid WARP cache: %v\n", err)
	} else if err == nil {
		fmt.Fprintln(stderr, "warning: cached WARP account is incomplete; registering a new one")
	}

	fmt.Fprintln(stdout, "Registering ephemeral Cloudflare WARP device...")
	account, err = registerWarpAccount(ctx)
	if err != nil {
		return nil, err
	}
	if err := saveWarpAccount(path, account); err != nil {
		fmt.Fprintf(stderr, "warning: could not cache WARP account: %v\n", err)
	} else {
		fmt.Fprintln(stdout, "Saved WARP account to", path)
	}
	return account, nil
}

func loadWarpAccount(path string) (*warpAccount, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var account warpAccount
	if err := json.Unmarshal(data, &account); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	return &account, nil
}

func saveWarpAccount(path string, account *warpAccount) error {
	data, err := json.MarshalIndent(account, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		file.Close()
		return err
	}
	if _, err := file.Write(data); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func (a *warpAccount) valid() bool {
	if a == nil || a.PrivateKey == "" || a.PeerPublicKey == "" {
		return false
	}
	if _, err := decodeKey(a.PrivateKey); err != nil {
		return false
	}
	if _, err := decodeKey(a.PeerPublicKey); err != nil {
		return false
	}
	if a.V4Address == "" && a.V6Address == "" {
		return false
	}
	return true
}

func decodeKey(value string) ([]byte, error) {
	key, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return nil, err
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("key is %d bytes, want 32", len(key))
	}
	return key, nil
}

func generateWireGuardKeypair() (privateKey, publicKey string, err error) {
	key, err := ecdh.X25519().GenerateKey(cryptorand.Reader)
	if err != nil {
		return "", "", err
	}
	privateKey = base64.StdEncoding.EncodeToString(key.Bytes())
	publicKey = base64.StdEncoding.EncodeToString(key.PublicKey().Bytes())
	return privateKey, publicKey, nil
}

func registerWarpAccount(ctx context.Context) (*warpAccount, error) {
	privateKey, publicKey, err := generateWireGuardKeypair()
	if err != nil {
		return nil, fmt.Errorf("generate WireGuard key: %w", err)
	}

	payload := struct {
		Key   string `json:"key"`
		TOS   string `json:"tos"`
		Type  string `json:"type"`
		Model string `json:"model"`
	}{
		Key:   publicKey,
		TOS:   time.Now().UTC().Format("2006-01-02T15:04:05.000") + "Z",
		Type:  "Android",
		Model: "PC",
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, warpAPIURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "okhttp/3.12.1")

	client := &http.Client{Timeout: 20 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("WARP registration request: %w", err)
	}
	defer resp.Body.Close()
	responseBody, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, fmt.Errorf("read WARP registration response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, fmt.Errorf("WARP registration failed: %s: %s", resp.Status, strings.TrimSpace(string(responseBody)))
	}

	var registration warpRegistrationResponse
	if err := json.Unmarshal(responseBody, &registration); err != nil {
		return nil, fmt.Errorf("parse WARP registration response: %w", err)
	}
	return warpAccountFromRegistration(&registration, privateKey, publicKey)
}

func warpAccountFromRegistration(registration *warpRegistrationResponse, privateKey, publicKey string) (*warpAccount, error) {
	if len(registration.Config.Peers) == 0 {
		return nil, fmt.Errorf("WARP registration returned no peers")
	}
	peer := registration.Config.Peers[0]
	account := &warpAccount{
		ID:             registration.ID,
		PrivateKey:     privateKey,
		PublicKey:      publicKey,
		PeerPublicKey:  peer.PublicKey,
		PeerEndpointV4: hostOnly(peer.Endpoint.V4),
		PeerEndpointV6: hostOnly(peer.Endpoint.V6),
		V4Address:      plainAddress(registration.Config.Interface.Addresses.V4),
		V6Address:      plainAddress(registration.Config.Interface.Addresses.V6),
	}
	if !account.valid() {
		return nil, fmt.Errorf("WARP registration returned an incomplete account")
	}
	return account, nil
}

// warpPeerEndpoint returns the WireGuard endpoint address. For a selected
// country it embeds the WARP IPv4 endpoint in that country's NAT64 /96 prefix,
// producing an IPv6 address such as 2602:fc59:b0:64::a29f:c006.
func warpPeerEndpoint(country string, account *warpAccount) (string, error) {
	base := warpDefaultHost
	if account != nil && account.PeerEndpointV4 != "" {
		base = hostOnly(account.PeerEndpointV4)
	}
	endpoint, err := netip.ParseAddr(base)
	if err != nil || !endpoint.Is4() {
		return "", fmt.Errorf("invalid WARP endpoint %q", base)
	}
	if country == "any" {
		return endpoint.String(), nil
	}

	prefixes := warpNAT64Prefixes[country]
	if len(prefixes) == 0 {
		return "", fmt.Errorf("WARP country %q has no verified NAT64 endpoint", country)
	}
	synthesized, err := synthesizeNAT64(prefixes[0], endpoint)
	if err != nil {
		return "", err
	}
	return synthesized.String(), nil
}

func synthesizeNAT64(prefix string, endpoint netip.Addr) (netip.Addr, error) {
	parsed, err := netip.ParsePrefix(prefix)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("parse NAT64 prefix %q: %w", prefix, err)
	}
	if parsed.Bits() != 96 {
		return netip.Addr{}, fmt.Errorf("NAT64 prefix %q is not /96", prefix)
	}
	if !endpoint.Is4() {
		return netip.Addr{}, fmt.Errorf("NAT64 endpoint %q is not IPv4", endpoint)
	}
	address := parsed.Masked().Addr().As16()
	v4 := endpoint.As4()
	copy(address[12:], v4[:])
	return netip.AddrFrom16(address), nil
}

func hostOnly(value string) string {
	value = strings.TrimSpace(value)
	if host, _, err := net.SplitHostPort(value); err == nil {
		return strings.Trim(host, "[]")
	}
	return strings.Trim(value, "[]")
}

func plainAddress(value string) string {
	if index := strings.IndexByte(value, '/'); index >= 0 {
		return value[:index]
	}
	return strings.TrimSpace(value)
}
