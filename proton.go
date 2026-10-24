package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	protonServerListURL  = "https://raw.githubusercontent.com/qdm12/gluetun-servers/main/pkg/servers/protonvpn.json"
	protonEndpointPort   = 51820
	protonDefaultAddress = "10.2.0.2/32"
	protonDefaultDNS     = "10.2.0.1"
	protonDefaultMTU     = 1420
	protonServerListTTL  = 24 * time.Hour
	protonServerListMax  = 8 << 20
)

type protonServer struct {
	VPN        string   `json:"vpn"`
	Country    string   `json:"country"`
	City       string   `json:"city"`
	ServerName string   `json:"server_name"`
	Hostname   string   `json:"hostname"`
	WGPubKey   string   `json:"wgpubkey"`
	Free       bool     `json:"free"`
	IPs        []string `json:"ips"`
}

type protonServerList struct {
	Version int            `json:"version"`
	Servers []protonServer `json:"servers"`
}

type protonChoice struct {
	Code  string
	Label string
}

func parseProtonServers(data []byte) ([]protonServer, error) {
	var list protonServerList
	if err := json.Unmarshal(data, &list); err != nil {
		return nil, fmt.Errorf("parse Proton server list: %w", err)
	}

	servers := make([]protonServer, 0, len(list.Servers))
	seen := make(map[string]bool)
	for _, server := range list.Servers {
		if !server.valid() || seen[server.ServerName] {
			continue
		}
		seen[server.ServerName] = true
		servers = append(servers, server)
	}
	if len(servers) == 0 {
		return nil, fmt.Errorf("Proton server list contains no free WireGuard servers")
	}

	sort.Slice(servers, func(i, j int) bool {
		a, b := servers[i], servers[j]
		if a.Country != b.Country {
			return a.Country < b.Country
		}
		if a.City != b.City {
			return a.City < b.City
		}
		return a.ServerName < b.ServerName
	})
	return servers, nil
}

func (s protonServer) valid() bool {
	if s.VPN != "wireguard" || !s.Free {
		return false
	}
	if protonCountryCode(s.ServerName) == "" {
		return false
	}
	if _, err := decodeKey(s.WGPubKey); err != nil {
		return false
	}
	_, err := s.endpoint()
	return err == nil
}

// endpoint returns the peer address. Proton's JSON carries one or more IPs and
// a hostname; the IP avoids a DNS lookup inside the tunnel. IPv4 is preferred
// when both families are present.
func (s protonServer) endpoint() (string, error) {
	var v6 string
	for _, raw := range s.IPs {
		addr, err := netip.ParseAddr(strings.TrimSpace(raw))
		if err != nil {
			continue
		}
		if addr.Is4() {
			return addr.String(), nil
		}
		if v6 == "" {
			v6 = addr.String()
		}
	}
	if v6 != "" {
		return v6, nil
	}
	if host := strings.TrimSpace(s.Hostname); host != "" {
		return host, nil
	}
	return "", fmt.Errorf("Proton server %q has no endpoint", s.ServerName)
}

func protonCountryCode(serverName string) string {
	prefix, _, _ := strings.Cut(serverName, "-")
	if len(prefix) != 2 {
		return ""
	}
	prefix = strings.ToLower(prefix)
	if !isASCIILetter(prefix[0]) || !isASCIILetter(prefix[1]) {
		return ""
	}
	return prefix
}

func protonCitySlug(city string) string {
	var b strings.Builder
	lastDash := false
	for _, r := range strings.ToLower(strings.TrimSpace(city)) {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
			b.WriteRune(r)
			lastDash = false
		default:
			if !lastDash && b.Len() > 0 {
				b.WriteByte('-')
				lastDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func protonCountryName(servers []protonServer, code string) string {
	for _, server := range servers {
		if protonCountryCode(server.ServerName) == code {
			return server.Country
		}
	}
	return ""
}

func protonCityName(servers []protonServer, country, slug string) string {
	for _, server := range servers {
		if protonCountryCode(server.ServerName) == country && protonCitySlug(server.City) == slug {
			return server.City
		}
	}
	return ""
}

func protonCountryCodes(servers []protonServer) []string {
	seen := make(map[string]bool)
	var codes []string
	for _, server := range servers {
		code := protonCountryCode(server.ServerName)
		if code == "" || seen[code] {
			continue
		}
		seen[code] = true
		codes = append(codes, code)
	}
	sort.Strings(codes)
	return codes
}

func protonCitySlugs(servers []protonServer, country string) []string {
	seen := make(map[string]bool)
	var slugs []string
	for _, server := range servers {
		if protonCountryCode(server.ServerName) != country {
			continue
		}
		slug := protonCitySlug(server.City)
		if slug == "" || seen[slug] {
			continue
		}
		seen[slug] = true
		slugs = append(slugs, slug)
	}
	sort.Strings(slugs)
	return slugs
}

func protonCityChoices(servers []protonServer) []string {
	seen := make(map[string]bool)
	var choices []string
	for _, server := range servers {
		code := protonCountryCode(server.ServerName) + "/" + protonCitySlug(server.City)
		if seen[code] {
			continue
		}
		seen[code] = true
		choices = append(choices, code)
	}
	sort.Strings(choices)
	return choices
}

// protonLocationChoices returns the numbered list used by --list and by
// numeric country/city selection. Entry 0 is always "any".
func protonLocationChoices(servers []protonServer) []protonChoice {
	type cityInfo struct {
		Name  string
		Count int
	}

	countries := make(map[string]string)
	cities := make(map[string]map[string]*cityInfo)
	for _, server := range servers {
		code := protonCountryCode(server.ServerName)
		if code == "" {
			continue
		}
		if _, ok := countries[code]; !ok {
			countries[code] = server.Country
		}
		slug := protonCitySlug(server.City)
		if slug == "" {
			continue
		}
		if cities[code] == nil {
			cities[code] = make(map[string]*cityInfo)
		}
		if cities[code][slug] == nil {
			cities[code][slug] = &cityInfo{Name: server.City}
		}
		cities[code][slug].Count++
	}

	codes := make([]string, 0, len(countries))
	for code := range countries {
		codes = append(codes, code)
	}
	sort.Slice(codes, func(i, j int) bool {
		if countries[codes[i]] != countries[codes[j]] {
			return countries[codes[i]] < countries[codes[j]]
		}
		return codes[i] < codes[j]
	})

	choices := []protonChoice{{Code: "any", Label: "Any free server (random)"}}
	for _, code := range codes {
		choices = append(choices, protonChoice{
			Code:  code,
			Label: countries[code] + " (any city)",
		})

		slugs := make([]string, 0, len(cities[code]))
		for slug := range cities[code] {
			slugs = append(slugs, slug)
		}
		sort.Slice(slugs, func(i, j int) bool {
			return cities[code][slugs[i]].Name < cities[code][slugs[j]].Name
		})
		for _, slug := range slugs {
			info := cities[code][slug]
			label := info.Name
			if info.Count > 1 {
				label = fmt.Sprintf("%s (%d servers)", info.Name, info.Count)
			}
			choices = append(choices, protonChoice{
				Code:  code + "/" + slug,
				Label: label,
			})
		}
	}
	return choices
}

func protonTUIChoices(servers []protonServer) []protonChoice {
	choices := protonLocationChoices(servers)
	return append(choices,
		protonChoice{Code: "random", Label: "Random city"},
		protonChoice{Code: "quit", Label: "Quit"},
	)
}

func protonCountryExists(servers []protonServer, code string) bool {
	for _, server := range servers {
		if protonCountryCode(server.ServerName) == code {
			return true
		}
	}
	return false
}

func protonCityExists(servers []protonServer, country, slug string) bool {
	for _, server := range servers {
		if protonCountryCode(server.ServerName) == country && protonCitySlug(server.City) == slug {
			return true
		}
	}
	return false
}

// resolveProtonChoice canonicalises "any", "random", "cc", or "cc/city".
func resolveProtonChoice(value string, servers []protonServer) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", "any":
		return "any", nil
	case "random":
		choices := protonCityChoices(servers)
		if len(choices) == 0 {
			return "", fmt.Errorf("no free Proton servers are available")
		}
		return choices[rand.IntN(len(choices))], nil
	}

	country, city, hasCity := strings.Cut(value, "/")
	if len(country) != 2 || !isASCIILetter(country[0]) || !isASCIILetter(country[1]) {
		return "", fmt.Errorf("invalid Proton location %q (use a two-letter country code, cc/city, any, or random)", value)
	}
	if !protonCountryExists(servers, country) {
		return "", fmt.Errorf("Proton country %q has no free WireGuard servers (available: %s)",
			country, strings.Join(protonCountryCodes(servers), ", "))
	}
	if !hasCity {
		return country, nil
	}

	slug := protonCitySlug(city)
	if slug == "" {
		return "", fmt.Errorf("invalid Proton city %q", city)
	}
	if !protonCityExists(servers, country, slug) {
		return "", fmt.Errorf("Proton city %q has no free WireGuard servers in %s (available: %s)",
			city, protonCountryName(servers, country), strings.Join(protonCitySlugs(servers, country), ", "))
	}
	return country + "/" + slug, nil
}

func parseProtonNumberChoice(value string, servers []protonServer) (string, error) {
	choices := protonLocationChoices(servers)
	if n, err := strconv.Atoi(strings.TrimSpace(value)); err == nil {
		if n == 0 {
			return "any", nil
		}
		if n >= 1 && n < len(choices) {
			return choices[n].Code, nil
		}
		return "", fmt.Errorf("number out of range (0 = any, 1-%d = country or city)", len(choices)-1)
	}
	return resolveProtonChoice(value, servers)
}

func selectProtonServer(servers []protonServer, choice string) (protonServer, error) {
	country, city, hasCity := strings.Cut(choice, "/")
	var matches []protonServer
	for _, server := range servers {
		if choice != "any" {
			if protonCountryCode(server.ServerName) != country {
				continue
			}
			if hasCity && protonCitySlug(server.City) != city {
				continue
			}
		}
		matches = append(matches, server)
	}
	if len(matches) == 0 {
		return protonServer{}, fmt.Errorf("no free Proton server matches %q", choice)
	}
	return matches[rand.IntN(len(matches))], nil
}

func protonConfigSettings() (address, dns string, mtu int, err error) {
	address = strings.TrimSpace(os.Getenv("ROUTER_PROTON_ADDRESS"))
	if address == "" {
		address = protonDefaultAddress
	}
	if !strings.Contains(address, "/") {
		if addr, parseErr := netip.ParseAddr(address); parseErr == nil {
			if addr.Is4() {
				address += "/32"
			} else {
				address += "/128"
			}
		}
	}
	if _, parseErr := netip.ParsePrefix(address); parseErr != nil {
		return "", "", 0, fmt.Errorf("invalid ROUTER_PROTON_ADDRESS %q: %w", address, parseErr)
	}

	dns = strings.TrimSpace(os.Getenv("ROUTER_PROTON_DNS"))
	if dns == "" {
		dns = protonDefaultDNS
	}
	if _, parseErr := netip.ParseAddr(dns); parseErr != nil {
		return "", "", 0, fmt.Errorf("invalid ROUTER_PROTON_DNS %q: %w", dns, parseErr)
	}

	mtu = protonDefaultMTU
	if value := strings.TrimSpace(os.Getenv("ROUTER_PROTON_MTU")); value != "" {
		parsed, parseErr := strconv.Atoi(value)
		if parseErr != nil || parsed < 1280 || parsed > 1500 {
			return "", "", 0, fmt.Errorf("invalid ROUTER_PROTON_MTU %q (use 1280-1500)", value)
		}
		mtu = parsed
	}
	return address, dns, mtu, nil
}

func protonEnvPath() string {
	if path := strings.TrimSpace(os.Getenv("ROUTER_ENV_FILE")); path != "" {
		return path
	}
	return ".env"
}

// protonPrivateKey reads WG from the environment or from .env and returns a
// canonical standard-base64 WireGuard private key.
func protonPrivateKey() (string, error) {
	value := strings.TrimSpace(os.Getenv("WG"))
	source := "WG environment variable"
	if value == "" {
		path := protonEnvPath()
		values, err := readDotEnv(path)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("Proton private key not found: set WG in %s or the environment", path)
			}
			return "", fmt.Errorf("read %s: %w", path, err)
		}
		value = strings.TrimSpace(values["WG"])
		source = path
	}
	if value == "" {
		return "", fmt.Errorf("Proton private key not found: set WG in %s or the environment", source)
	}

	key, err := decodeProtonKey(value)
	if err != nil {
		return "", fmt.Errorf("invalid Proton WireGuard private key in %s: %w", source, err)
	}
	return base64.StdEncoding.EncodeToString(key), nil
}

func readDotEnv(path string) (map[string]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	values := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		line = strings.TrimPrefix(line, "export ")
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		value = strings.TrimSpace(value)
		quoted := false
		if len(value) >= 2 {
			quote := value[0]
			if (quote == '"' || quote == '\'') && value[len(value)-1] == quote {
				value = value[1 : len(value)-1]
				quoted = true
			}
		}
		if !quoted {
			if index := strings.Index(value, " #"); index >= 0 {
				value = strings.TrimSpace(value[:index])
			}
		}
		values[key] = value
	}
	return values, nil
}

func decodeProtonKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, fmt.Errorf("key is empty")
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		key, err := encoding.DecodeString(value)
		if err != nil {
			continue
		}
		if len(key) != 32 {
			return nil, fmt.Errorf("key decodes to %d bytes, want 32", len(key))
		}
		return key, nil
	}
	return nil, fmt.Errorf("key is not valid base64 (%d characters)", len(value))
}

func protonServerListPath() string {
	if path := strings.TrimSpace(os.Getenv("ROUTER_PROTON_CACHE")); path != "" {
		return path
	}
	return filepath.Join(os.TempDir(), "router-"+strconv.Itoa(os.Geteuid()), "proton-servers.json")
}

func loadProtonServers(ctx context.Context) ([]protonServer, error) {
	if path := strings.TrimSpace(os.Getenv("ROUTER_PROTON_SERVERS")); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read ROUTER_PROTON_SERVERS %s: %w", path, err)
		}
		servers, err := parseProtonServers(data)
		if err != nil {
			return nil, fmt.Errorf("parse ROUTER_PROTON_SERVERS %s: %w", path, err)
		}
		return servers, nil
	}

	cachePath := protonServerListPath()
	cached, cacheErr := os.ReadFile(cachePath)
	if cacheErr == nil {
		if info, statErr := os.Stat(cachePath); statErr == nil && time.Since(info.ModTime()) < protonServerListTTL {
			if servers, parseErr := parseProtonServers(cached); parseErr == nil {
				return servers, nil
			}
		}
	}

	data, fetchErr := fetchProtonServerList(ctx)
	if fetchErr != nil {
		if cacheErr == nil {
			if servers, parseErr := parseProtonServers(cached); parseErr == nil {
				fmt.Fprintf(stderr, "warning: could not refresh Proton server list, using cache: %v\n", fetchErr)
				return servers, nil
			}
		}
		return nil, fetchErr
	}

	servers, err := parseProtonServers(data)
	if err != nil {
		return nil, err
	}
	if err := writeProtonCache(cachePath, data); err != nil {
		fmt.Fprintf(stderr, "warning: could not cache Proton server list: %v\n", err)
	}
	return servers, nil
}

func fetchProtonServerList(ctx context.Context) ([]byte, error) {
	url := protonServerListURL
	if override := strings.TrimSpace(os.Getenv("ROUTER_PROTON_SERVERS_URL")); override != "" {
		url = override
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build Proton server list request: %w", err)
	}
	req.Header.Set("User-Agent", "router/1.0")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("download Proton server list: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download Proton server list: %s", resp.Status)
	}

	data, err := io.ReadAll(io.LimitReader(resp.Body, protonServerListMax+1))
	if err != nil {
		return nil, fmt.Errorf("read Proton server list: %w", err)
	}
	if len(data) > protonServerListMax {
		return nil, fmt.Errorf("Proton server list is larger than %d bytes", protonServerListMax)
	}
	return data, nil
}

func writeProtonCache(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".proton-servers-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
