package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
)

const (
	defaultListenPort      = 10808
	defaultTorInterface    = "sb-tor"
	defaultWarpInterface   = "sb-warp"
	defaultProtonInterface = "sb-proton"
)

type options struct {
	backend       string
	country       string
	listenPort    int
	proxyOnly     bool
	clean         bool
	list          bool
	noVerify      bool
	noInteractive bool
	interfaceName string
}

func main() {
	opts, err := parseFlags(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(stderr, "error:", err)
		os.Exit(2)
	}
	if opts.list {
		var servers []protonServer
		if opts.backend == backendProton {
			var err error
			servers, err = loadProtonServers(context.Background())
			if err != nil {
				fmt.Fprintln(stderr, "error:", err)
				os.Exit(1)
			}
		}
		printCountryList(opts.backend, servers)
		return
	}
	if err := run(opts); err != nil {
		fmt.Fprintln(stderr, "error:", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) (options, error) {
	var opts options
	fs := flag.NewFlagSet("router", flag.ContinueOnError)
	fs.StringVar(&opts.backend, "b", backendWarp, "backend: warp, proton, or tor")
	fs.StringVar(&opts.backend, "backend", backendWarp, "backend: warp, proton, or tor")
	fs.StringVar(&opts.country, "c", "any", "exit country or city: two-letter code, cc/city (Proton), any, or random")
	fs.StringVar(&opts.country, "country", "any", "exit country or city: two-letter code, cc/city (Proton), any, or random")
	fs.IntVar(&opts.listenPort, "listen-port", defaultListenPort, "local mixed proxy port")
	fs.BoolVar(&opts.proxyOnly, "proxy-only", false, "force proxy mode even when run as root")
	fs.BoolVar(&opts.clean, "clean", false, "clear cached Tor data before connecting (Tor backend)")
	fs.BoolVar(&opts.list, "list", false, "list countries and exit")
	fs.BoolVar(&opts.noVerify, "no-verify", false, "skip exit verification")
	fs.BoolVar(&opts.noInteractive, "no-interactive", false, "disable the interactive country switcher")
	fs.StringVar(&opts.interfaceName, "interface", "", "TUN interface name (default: sb-warp, sb-proton, or sb-tor)")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `router - Cloudflare WARP, Proton VPN, and Tor router powered by sing-box

Usage:
  router [flags]

Examples:
  sudo router                            # WARP, automatic Cloudflare edge
  sudo router -c us                      # WARP, US Double WARP
  sudo router -b proton -c us/san-jose   # free Proton WireGuard, San Jose
  sudo router -b tor -c jp               # Tor
  router --proxy-only -c any             # local proxy instead of TUN

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return opts, err
	}
	if fs.NArg() > 0 {
		return opts, fmt.Errorf("unexpected argument: %s", fs.Arg(0))
	}

	backend, err := validateBackend(opts.backend)
	if err != nil {
		return opts, err
	}
	opts.backend = backend

	if opts.listenPort < 1 || opts.listenPort > 65535 {
		return opts, fmt.Errorf("invalid listen port: %d", opts.listenPort)
	}

	interfaceSet := false
	fs.Visit(func(f *flag.Flag) {
		if f.Name == "interface" {
			interfaceSet = true
		}
	})
	if !interfaceSet {
		switch opts.backend {
		case backendWarp:
			opts.interfaceName = defaultWarpInterface
		case backendProton:
			opts.interfaceName = defaultProtonInterface
		default:
			opts.interfaceName = defaultTorInterface
		}
	}
	if opts.interfaceName == "" {
		return opts, fmt.Errorf("interface name must not be empty")
	}
	return opts, nil
}
