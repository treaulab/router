# router

A bare-minimum Go port of the Python `tor.py` and `warp.py` prototypes. It
routes traffic through **Cloudflare WARP** (default), **Proton VPN**,
**Proton -> WARP**, or **Tor** using a `sing-box` TUN interface or a local
mixed proxy.

All four backends are implemented. WARP registration and WireGuard key
generation use only the Go standard library; `warp-cli`, `wgcf`, and
third-party WARP libraries are not used. The Proton backend consumes only
Proton's **free** WireGuard servers.

## Requirements

- Linux (NixOS tested); this build uses Unix process and interface APIs
- Go 1.26+
- `sing-box` in `PATH` (built with `with_gvisor` for the userspace TUN stack and
  `with_wireguard` for the WARP endpoint)
- `tor` installed for the Tor backend, or `ROUTER_TOR_BINARY` pointing at it
- a Proton VPN WireGuard private key in `WG` (`WG=...` in `.env` or the
  environment) for the Proton backend
- root for TUN mode (`CAP_NET_ADMIN`); otherwise it runs as a local mixed proxy
- For WARP `-c us`: no native IPv6 is required; the router uses Double WARP
  over IPv4 and dials the verified US/Fremont NAT64 endpoint from inside the
  outer tunnel

On NixOS the Tor binary and GeoIP database are discovered from `/nix/store`.

## Usage

```sh
# Whole-system TUN through WARP (default), automatic Cloudflare edge
sudo go run .

# WARP with the verified US (Fremont) Double WARP exit
sudo go run . -c us

# Free Proton WireGuard in a specific city
sudo go run . -b proton -c us/san-jose

# Free Proton WireGuard, any city in a country
sudo go run . -b proton -c ca

# Proton city as transport, WARP as the final exit
sudo go run . -b proton-warp -c ch/zurich

# Whole-system TUN through Tor, random exit country
sudo go run . -b tor -c random

# Local HTTP + SOCKS5 proxy instead of TUN
go run . --proxy-only -c any
go run . -b tor --proxy-only -c de

# List countries/cities for the selected backend
go run . --list
go run . -b proton --list
go run . -b tor --list
```

Build:

```sh
go build -o router .
```

## Backends

`-b warp` (default) registers an ephemeral Cloudflare WARP device over HTTPS,
caches it, and configures a sing-box WireGuard endpoint. `-b proton` reads the
free Proton server list and connects directly to a free Proton WireGuard
server. `-b proton-warp` uses a free Proton WireGuard server as the outer
transport and runs WARP inside it. `-b tor` starts sing-box's Tor outbound.

### WARP accounts

The outer WARP account is cached in `warp_account.json` in the current
directory. Set `ROUTER_WARP_ACCOUNT` to use a different path. If the file is
missing or invalid, a new ephemeral device is registered automatically.

When `-c us` is selected, a second inner account is registered lazily and
cached in `warp_inner_account.json`. Set `ROUTER_WARP_INNER_ACCOUNT` to use a
different path. Both files contain WireGuard private keys, so they are written
with mode `0600`.

### WARP countries

WARP normally uses Cloudflare's nearest edge. `-c any` uses the normal IPv4
WARP endpoint: a single hop with no IPv6 requirement.

`-c us` uses Double WARP. An outer WARP tunnel is established over IPv4, then
an inner WARP tunnel is dialed through it to the verified US/Fremont NAT64
endpoint. Cloudflare receives the inner handshake from the Fremont NAT64
gateway and exits from the US (typically the SJC edge).

| Code | Country       | NAT64 prefix           | Mode        |
| ---- | ------------- | ---------------------- | ----------- |
| `us` | United States | `2602:fc59:b0:64::/96` | Double WARP |

Public European NAT64 gateways (Germany, Finland, Netherlands) currently block
Cloudflare WARP egress, so `-c de`, `-c fi`, and `-c nl` are rejected by the
WARP backend with a clear error. Use `-b tor` for those countries instead.

`-c random` picks from the verified WARP country set, which currently contains
only `us`. No native IPv6 is needed for `-c us`; the outer tunnel carries the
inner tunnel's IPv6 traffic over IPv4.

### Proton VPN (free servers)

The Proton backend downloads the server list from
`https://raw.githubusercontent.com/qdm12/gluetun-servers/main/pkg/servers/protonvpn.json`
and accepts a server only when it is **WireGuard** and has **`free: true`**.
Paid Proton servers, OpenVPN servers, servers with an invalid public key, and
servers without an endpoint are discarded. It does not fall back to paid
servers.

The list is cached for 24 hours at `/tmp/router-<uid>/proton-servers.json`.
Override the cache path with `ROUTER_PROTON_CACHE`, use a local JSON file with
`ROUTER_PROTON_SERVERS`, or change the download URL with
`ROUTER_PROTON_SERVERS_URL`.

The private key comes from `WG` in the environment or from `.env`:

```sh
# .env
WG=<your Proton WireGuard private key>
```

`ROUTER_ENV_FILE` selects a different dotenv file. The key must be a 32-byte
WireGuard private key encoded as base64 (normally 44 characters). It is never
printed by the router.

Country and city selection:

```sh
sudo ./router -b proton -c any          # random free server
sudo ./router -b proton -c random       # random free city
sudo ./router -b proton -c us           # any free US city
sudo ./router -b proton -c us/san-jose  # a free San Jose server
```

City names are matched case-insensitively and slugged (`San Jose` ->
`san-jose`). Use `./router -b proton --list` to see the exact free city list.
Inside a city, the router picks a random free server.

The generated WireGuard endpoint uses Proton's defaults:

| Setting | Default | Override |
| ------- | ------- | -------- |
| Address | `10.2.0.2/32` | `ROUTER_PROTON_ADDRESS` |
| DNS | `10.2.0.1` | `ROUTER_PROTON_DNS` |
| MTU | `1420` | `ROUTER_PROTON_MTU` (1280-1500) |
| Peer port | `51820` | fixed |

The DNS server is routed explicitly through `proton-out`, and private/LAN
traffic bypasses the tunnel. Proton carries UDP normally, so unlike Tor there
is no UDP reject rule.

Switching cities restarts the sing-box engine. Proton free servers are shared
and may be busy; if a server does not complete a handshake, choose another
city or run the switch again to pick a different server.

### Proton -> WARP

`-b proton-warp` chains two WireGuard endpoints:

```
you -> free Proton server (outer) -> Cloudflare WARP (inner) -> internet
```

`-c` selects the **Proton** country or city, using the same `cc` / `cc/city`
syntax and free-server filtering as the Proton backend. WARP registers a
normal inner device and connects through the selected Proton server.

Important: the final internet exit is **Cloudflare WARP**, not Proton. The
Proton city only controls the transport path into Cloudflare. Because Cloudflare
chooses the WARP edge, the final country is not guaranteed to match the Proton
city; this is not a way to force WARP into an arbitrary country.

```sh
sudo ./router -b proton-warp -c ch/zurich
sudo ./router -b proton-warp -c us/san-jose
sudo ./router -b proton-warp -c any
```

The TUI lists Proton countries and cities for this backend too, and restarting
after a switch regenerates both WireGuard endpoints.

## Interactive switching

When run in a terminal, the router opens a small Bubble Tea interface. The
current exit country (or Proton country/city) is marked `(current)`.

```
up/down, j/k    move the selection
enter           switch to the selected country
r               switch to a random country
q, Ctrl+C       quit
```

Switching restarts the sing-box engine, so the TUN interface is recreated and
active connections are dropped. If you quit while a switch is in progress, the
interface waits for that switch to finish before exiting. Zero-downtime
hot-swapping is the next step. Use `--no-interactive` to disable the interface.

## Flags

```
-b, --backend       backend: warp, proton, proton-warp, or tor (default: warp)
-c, --country       two-letter code, cc/city (Proton), any, or random (default: any)
--listen-port       local mixed proxy port (default: 10808)
--proxy-only        force proxy mode even when run as root
--clean             clear cached Tor data before connecting (Tor backend)
--list              list countries/cities and exit
--no-verify         skip exit verification
--no-interactive    disable the interactive country switcher
--interface         TUN interface name (default: sb-warp, sb-proton, sb-proton-warp, or sb-tor)
```

## Notes

- Tor TUN mode rejects non-DNS UDP because Tor only carries TCP. Browsers fall
  back to TCP automatically. WARP and Proton carry UDP normally.
- Tor TUN mode sends DNS through Tor over TCP.
- The Tor data directory is cached under `/tmp/router-<uid>/tor` for faster
  bootstrap; use `--clean` to reset it.
- The generated sing-box config and logs go to `/tmp/router-<uid>/`; the log
  file is `/tmp/router-<uid>/sing-box.log`.
- `-c us` adds a second WireGuard hop, so it is slower than `-c any`. The
  Fremont NAT64 endpoint is the only public gateway verified to complete the
  inner handshake through WARP; other gateways were not enabled.
- The WARP registration endpoint is `https://api.cloudflareclient.com/v0a2158/reg`;
  keys are generated with `crypto/ecdh` (X25519).
- Proton free servers are filtered from the downloaded list at startup. Paid
  servers are never selected, even if a paid server is requested by country or
  city.
- Proton city selection controls the server city. It does not guarantee how
  third-party geolocation databases label the exit IP.
- `-b proton-warp` uses the Proton city only as transport. Its final exit is
  Cloudflare WARP, and Cloudflare selects that egress.
