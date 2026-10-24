package main

import (
	"fmt"
	"math/rand/v2"
	"os"
	"strings"
)

const (
	backendTor    = "tor"
	backendWarp   = "warp"
	backendProton = "proton"
)

type country struct {
	Code string
	Name string
}

// Mirrors the list from the Python prototype.
var commonCountries = []country{
	{"de", "Germany"},
	{"nl", "Netherlands"},
	{"ch", "Switzerland"},
	{"us", "United States"},
	{"gb", "United Kingdom"},
	{"fr", "France"},
	{"jp", "Japan"},
	{"ca", "Canada"},
	{"se", "Sweden"},
	{"at", "Austria"},
	{"fi", "Finland"},
	{"no", "Norway"},
	{"ro", "Romania"},
	{"pl", "Poland"},
	{"is", "Iceland"},
}

// WARP country selection works by synthesizing a NAT64 IPv6 endpoint from a
// country's NAT64 prefix. Only countries with a verified, reachable prefix are
// listed here; the US/Fremont endpoint is the only one that currently completes
// a WireGuard handshake through an outer WARP tunnel.
var warpCountryCodes = []string{"us"}

// Public European NAT64 gateways block Cloudflare WARP egress, so these
// countries cannot be offered by the WARP backend. They remain available
// through Tor.
var warpBlockedCountries = map[string]bool{
	"de": true,
	"fi": true,
	"nl": true,
}

func validateBackend(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", backendWarp:
		return backendWarp, nil
	case backendTor:
		return backendTor, nil
	case backendProton:
		return backendProton, nil
	default:
		return "", fmt.Errorf("invalid backend %q (use warp, proton, or tor)", value)
	}
}

func backendName(backend string) string {
	switch backend {
	case backendWarp:
		return "WARP"
	case backendProton:
		return "Proton VPN"
	default:
		return "Tor"
	}
}

func countryName(code string) string {
	if code == "any" {
		return "Any (automatic)"
	}
	for _, c := range commonCountries {
		if c.Code == code {
			return c.Name
		}
	}
	return strings.ToUpper(code)
}

func countryLabel(backend, code string, servers []protonServer) string {
	if backend == backendProton {
		return protonChoiceLabel(code, servers)
	}
	if code == "any" {
		if backend == backendWarp {
			return "Automatic (Cloudflare edge)"
		}
		return "Any (automatic)"
	}
	return countryName(code)
}

func protonChoiceLabel(code string, servers []protonServer) string {
	code = strings.ToLower(strings.TrimSpace(code))
	switch code {
	case "", "any":
		return "Any free server (random)"
	case "random":
		return "Random city"
	}

	country, city, hasCity := strings.Cut(code, "/")
	name := protonCountryName(servers, country)
	if name == "" {
		name = strings.ToUpper(country)
	}
	if !hasCity {
		return name + " (any city)"
	}
	cityName := protonCityName(servers, country, city)
	if cityName == "" {
		cityName = strings.ReplaceAll(city, "-", " ")
	}
	return cityName + ", " + name
}

func resolveCountry(value string) (string, error) {
	return resolveCountryForBackend(backendTor, value)
}

func resolveCountryForBackend(backend, value string) (string, error) {
	if backend == backendProton {
		return "", fmt.Errorf("Proton locations require the free server list")
	}
	value = strings.ToLower(strings.TrimSpace(value))
	switch value {
	case "", "any":
		return "any", nil
	case "random":
		codes := countryCodes(backend)
		return codes[rand.IntN(len(codes))], nil
	}
	if len(value) == 2 && isASCIILetter(value[0]) && isASCIILetter(value[1]) {
		if backend == backendWarp {
			if warpBlockedCountries[value] {
				return "", fmt.Errorf("WARP country %q is unavailable: public European NAT64 gateways block Cloudflare WARP egress; use -b tor -c %s instead", value, value)
			}
			if !isWarpCountry(value) {
				return "", fmt.Errorf("WARP country %q is not supported (available: %s, or any)",
					value, strings.Join(warpCountryCodes, ", "))
			}
		}
		return value, nil
	}
	return "", fmt.Errorf("invalid country %q (use a two-letter code, any, or random)", value)
}

func randomCountry() string {
	return commonCountries[rand.IntN(len(commonCountries))].Code
}

func randomCountryForBackend(backend string) string {
	codes := countryCodes(backend)
	if len(codes) == 0 {
		return "any"
	}
	return codes[rand.IntN(len(codes))]
}

func isASCIILetter(b byte) bool {
	return b >= 'a' && b <= 'z' || b >= 'A' && b <= 'Z'
}

func isWarpCountry(code string) bool {
	for _, c := range warpCountryCodes {
		if c == code {
			return true
		}
	}
	return false
}

func countryCodes(backend string) []string {
	if backend == backendWarp {
		return warpCountryCodes
	}
	if backend == backendProton {
		return nil
	}
	codes := make([]string, len(commonCountries))
	for i, c := range commonCountries {
		codes[i] = c.Code
	}
	return codes
}

func printCountryList(backend string, servers []protonServer) {
	if backend == backendProton {
		for i, choice := range protonLocationChoices(servers) {
			fmt.Fprintf(stdout, "%2d  %-14s %s\n", i, choice.Code, choice.Label)
		}
		fmt.Fprintf(stdout, "    %-14s %s\n", "random", "Random city")
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "Only free Proton WireGuard servers are listed.")
		fmt.Fprintln(stdout, "Pick a city with -c cc/city, e.g. -c us/san-jose.")
		return
	}

	fmt.Fprintf(stdout, "%2d  %-8s %s\n", 0, "any", countryLabel(backend, "any", nil))
	for i, c := range countryCodes(backend) {
		fmt.Fprintf(stdout, "%2d  %-8s %s\n", i+1, c, countryName(c))
	}
	fmt.Fprintf(stdout, "    %-8s %s\n", "random", "Random country")
	if backend == backendWarp {
		fmt.Fprintln(stdout)
		fmt.Fprintln(stdout, "WARP country shifting currently supports only the verified US (Fremont) endpoint.")
		fmt.Fprintln(stdout, "de, fi, and nl are unavailable: public European NAT64 gateways block Cloudflare WARP egress.")
		fmt.Fprintln(stdout, "Use -b tor for those countries.")
	}
}

func nextCountry(current string) string {
	return nextCountryForBackend(backendTor, current)
}

func nextCountryForBackend(backend, current string) string {
	codes := countryCodes(backend)
	if len(codes) == 0 {
		return "any"
	}
	if current == "any" {
		return codes[0]
	}
	for i, code := range codes {
		if code == current {
			return codes[(i+1)%len(codes)]
		}
	}
	return "any"
}

func isTerminal(f *os.File) bool {
	info, err := f.Stat()
	if err != nil {
		return false
	}
	return info.Mode()&os.ModeCharDevice != 0
}
