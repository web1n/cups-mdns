# cups-mdns

CUPS printer discovery bridge — queries a CUPS server via IPP and advertises shared printers through mDNS.

Two packages:

| Package | Description |
|---|---|
| `cups-mdns` | Background daemon that polls CUPS and runs a built-in mDNS responder |
| `cups-mdns-print` | Standalone CLI tool to query a CUPS server and list printers |

## Build (native)

```bash
cd cups-mdns
make
```

Requires `libcurl` and `libresolv`. Produces `out/cups-mdns` and `out/cups-mdns-print`.

## Build (OpenWrt)

Add to `feeds.conf`:

```
src-git cups_mdns https://github.com/web1n/cups-mdns.git
```

```bash
./scripts/feeds update cups_mdns
./scripts/feeds install cups-mdns cups-mdns-print luci-app-cups-mdns
make menuconfig
# Network → Printing → cups-mdns, cups-mdns-print
# LuCI → Applications → luci-app-cups-mdns
```

## Usage

```bash
# Daemon
cups-mdns --host 192.168.31.115 --port 631

# Print tool
cups-mdns-print -H 192.168.31.115 -P 631
```

### Options

| Flag | Default | Description |
|---|---|---|
| `-H, --host` | required | CUPS server IPv4 address |
| `-P, --port` | required | CUPS server port |
| `-n, --hostname` | `cups-proxy` | mDNS hostname (without `.local`) |
| `-I, --iface` | auto | Network interface for mDNS multicast |
| `-i, --interval` | `360` | CUPS poll interval (seconds) |
| `-t, --timeout` | `5` | HTTP request timeout (seconds) |
| `-d, --debug` | off | Verbose mDNS logging |
| `-l, --loopback` | off | Enable multicast loopback |

## How it works

```
┌──────────┐  IPP every 360s   ┌───────────────┐
│   CUPS   │ ←───────────────  │   cups-mdns   │
│  server  │ ───────────────→  │     daemon    │
└──────────┘   printer list    │               │
                               │ mDNS announce │  224.0.0.251:5353
                               └───────┬───────┘
                                       │
                          ┌────────────▼──────────────┐
                          │    Clients on the LAN     │
                          │   (mDNS + IPP capable)    │
                          └───────────────────────────┘
```

When the printer list changes, services are added/removed automatically.

## License

Apache-2.0
