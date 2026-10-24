# router

A bare-minimum Go port of the Python `tor.py` prototype: routes all traffic
through Tor using a `sing-box` TUN interface.

Only the **sing-box Tor backend** is implemented for now. WARP and other
backends are not.

## Requirements

- Linux (NixOS tested); this build uses Unix process and interface APIs
- Go 1.26+
- `sing-box` in `PATH` (built with `with_gvisor` for the userspace TUN stack)
- `tor` installed, or `ROUTER_TOR_BINARY` pointing at it
- root for TUN mode (`CAP_NET_ADMIN`); otherwise it runs as a local mixed proxy

On NixOS the Tor binary and GeoIP database are discovered from `/nix/store`.

## Usage

```sh
# Whole-system TUN through Tor, random exit country
sudo go run . -c random

# Specific exit country
sudo go run . -c jp

# Local HTTP + SOCKS5 proxy instead of TUN
go run . --proxy-only -c de

# List countries
go run . --list
```

Build:

```sh
go build -o router .
```

## Interactive switching

When run in a terminal, the router accepts commands:

```
<number|code>   switch exit country
n               next country
r               random country
l               list countries
s               status
q               quit
```

Switching currently restarts the sing-box engine, so the TUN interface is
recreated and active connections are dropped. Zero-downtime hot-swapping is the
next step.

## Flags

```
-c, --country       two-letter code, any, or random (default: any)
--listen-port       local mixed proxy port (default: 10808)
--proxy-only        force proxy mode even when run as root
--clean             clear cached Tor data before connecting
--list              list countries and exit
--no-verify         skip exit verification
--no-interactive    do not read switch commands from stdin
--interface         TUN interface name (default: sb-tor)
```

## Notes

- TUN mode rejects non-DNS UDP because Tor only carries TCP. Browsers fall back
  to TCP automatically.
- DNS in TUN mode is sent through Tor over TCP.
- The Tor data directory is cached under `/tmp/router-<uid>/tor` for faster
  bootstrap; use `--clean` to reset it.
- `sing-box` logs go to `/tmp/router-<uid>/sing-box.log`.
