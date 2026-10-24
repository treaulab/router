package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
)

func findTorBinary() (string, error) {
	if path := os.Getenv("ROUTER_TOR_BINARY"); path != "" {
		if _, err := os.Stat(path); err != nil {
			return "", fmt.Errorf("ROUTER_TOR_BINARY: %w", err)
		}
		return path, nil
	}
	if path, err := exec.LookPath("tor"); err == nil {
		return path, nil
	}
	// NixOS keeps Tor in the store and it is often not on PATH.
	matches, _ := filepath.Glob("/nix/store/*tor-0.*/bin/tor")
	if len(matches) > 0 {
		return matches[0], nil
	}
	return "", fmt.Errorf("tor executable not found; install Tor or set ROUTER_TOR_BINARY")
}

func findGeoIP() (string, string) {
	geoip := os.Getenv("ROUTER_GEOIP_FILE")
	geoip6 := os.Getenv("ROUTER_GEOIP6_FILE")

	if geoip == "" {
		if matches, _ := filepath.Glob("/nix/store/*tor*-geoip*/share/tor/geoip"); len(matches) > 0 {
			geoip = matches[0]
		} else {
			for _, candidate := range []string{"/usr/share/tor/geoip", "/var/lib/tor/geoip"} {
				if _, err := os.Stat(candidate); err == nil {
					geoip = candidate
					break
				}
			}
		}
	}
	if geoip6 == "" {
		if matches, _ := filepath.Glob("/nix/store/*tor*-geoip*/share/tor/geoip6"); len(matches) > 0 {
			geoip6 = matches[0]
		} else {
			for _, candidate := range []string{"/usr/share/tor/geoip6", "/var/lib/tor/geoip6"} {
				if _, err := os.Stat(candidate); err == nil {
					geoip6 = candidate
					break
				}
			}
		}
	}
	return geoip, geoip6
}
