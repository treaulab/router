package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
)

const (
	defaultListenPort = 10808
	defaultInterface  = "sb-tor"
)

type options struct {
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
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(2)
	}
	if opts.list {
		printCountryList()
		return
	}
	if err := run(opts); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) (options, error) {
	var opts options
	fs := flag.NewFlagSet("router", flag.ContinueOnError)
	fs.StringVar(&opts.country, "c", "any", "exit country: two-letter code, any, or random")
	fs.StringVar(&opts.country, "country", "any", "exit country: two-letter code, any, or random")
	fs.IntVar(&opts.listenPort, "listen-port", defaultListenPort, "local mixed proxy port")
	fs.BoolVar(&opts.proxyOnly, "proxy-only", false, "force proxy mode even when run as root")
	fs.BoolVar(&opts.clean, "clean", false, "clear cached Tor data before connecting")
	fs.BoolVar(&opts.list, "list", false, "list countries and exit")
	fs.BoolVar(&opts.noVerify, "no-verify", false, "skip exit verification")
	fs.BoolVar(&opts.noInteractive, "no-interactive", false, "do not read switch commands from stdin")
	fs.StringVar(&opts.interfaceName, "interface", defaultInterface, "TUN interface name")
	fs.Usage = func() {
		fmt.Fprintf(fs.Output(), `router - Tor TUN router powered by sing-box

Usage:
  router [flags]

Examples:
  sudo router -c jp
  sudo router -c random
  router --proxy-only -c de

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
	if opts.listenPort < 1 || opts.listenPort > 65535 {
		return opts, fmt.Errorf("invalid listen port: %d", opts.listenPort)
	}
	if opts.interfaceName == "" {
		return opts, fmt.Errorf("interface name must not be empty")
	}
	return opts, nil
}
