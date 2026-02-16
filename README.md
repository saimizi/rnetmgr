# rnetmgr

A simple, event-driven network interface manager for Linux written in Rust.

rnetmgr monitors Ethernet network interfaces via netlink and automatically configures them based on a JSON configuration file. It supports static IPv4 addressing, DHCP client mode, and DHCP server mode with optional NAT routing between interfaces.

## Features

- **Netlink-based monitoring** - Zero-polling interface and address event handling
- **Static IPv4** - Assign fixed IP addresses to interfaces via rtnetlink
- **DHCP Client** - Automatically start `dhcpcd` when an interface appears
- **DHCP Server** - Run a DHCP server (Kea DHCPv4 or dnsmasq) on an interface with a configurable IP pool
- **NAT Routing** - Optional iptables-based IP masquerade between interfaces
- **IPC (optional)** - Query interface state from external clients via `ipcon-sys`

## Building

```sh
cargo build --release
```

The binary is produced at `target/release/rnetmgr`.

### Cross-compilation for aarch64

Place ARM64 libnl libraries under an `arm64/` directory at the project root, then:

```sh
cargo build --release --target aarch64-unknown-linux-gnu
```

### Optional features

| Feature | Description |
|---------|-------------|
| `enable_ipcon` | Enable IPC support for external clients to query network state |

```sh
cargo build --release --features enable_ipcon
```

## Configuration

rnetmgr reads a JSON configuration file (default: `/etc/rnetmgr.json`).

### Format

```json
{
  "netifs": [
    {
      "ifname": "eth0",
      "iftype": "Ethernet",
      "addr_type": "DHCP"
    },
    {
      "ifname": "eth1",
      "iftype": "Ethernet",
      "addr_type": "Static",
      "ipv4": "192.168.1.10/24"
    },
    {
      "ifname": "eth2",
      "iftype": "Ethernet",
      "addr_type": "DHCPServer",
      "ipv4": "192.168.28.2/24",
      "routeif": "eth0"
    }
  ]
}
```

### Fields

| Field | Required | Description |
|-------|----------|-------------|
| `ifname` | Yes | Network interface name |
| `iftype` | Yes | Interface type (currently `Ethernet` only) |
| `addr_type` | Yes | `DHCP`, `Static`, or `DHCPServer` |
| `ipv4` | For `Static` / `DHCPServer` | IPv4 address in CIDR notation (e.g. `192.168.1.10/24`) |
| `routeif` | No | Outbound interface for NAT routing (used with `DHCPServer`) |

### Address types

- **DHCP** - Starts `/sbin/dhcpcd` on the interface when it appears.
- **Static** - Assigns the specified IPv4 address via rtnetlink.
- **DHCPServer** - Assigns the specified IPv4 address and starts a DHCP server for connected clients. If `routeif` is set, NAT routing is configured between this interface and the outbound interface.

## DHCP Server

rnetmgr supports two DHCP server backends:

### Kea DHCPv4 (default)

Requires `/usr/sbin/kea-dhcp4` and a template configuration file (default: `/etc/dhcp4-template.conf`). rnetmgr generates a runtime config from the template, substituting the interface name and network parameters.

### dnsmasq

Use the `-n` / `--dnsmasq` flag to use dnsmasq instead of Kea. No template file is needed; rnetmgr passes the DHCP range and interface directly as command-line arguments.

## Usage

```
rnetmgr [OPTIONS]

Options:
  -c, --config-file <CONFIG_FILE>  Path to JSON config file [default: /etc/rnetmgr.json]
  -d, --dhcp-conf <DHCP_CONF>      Path to Kea DHCP4 template [default: /etc/dhcp4-template.conf]
  -n, --dnsmasq                    Use dnsmasq instead of Kea DHCPv4
  -v, --verbose                    Increase log verbosity (-v for DEBUG, -vv for TRACE)
  -h, --help                       Print help information
  -V, --version                    Print version information
```

### Examples

Run with default settings:

```sh
rnetmgr -c /etc/rnetmgr.json
```

Run with dnsmasq and debug logging:

```sh
rnetmgr -c /etc/rnetmgr.json -n -v
```

## Installation as a systemd service

1. Copy the binary and configuration files:

```sh
sudo cp target/release/rnetmgr /usr/sbin/rnetmgr
sudo cp rnetmgr.json /etc/rnetmgr.json
sudo cp dhcp4-template.conf /etc/dhcp4-template.conf        # if using Kea
```

2. Install the service unit:

```sh
sudo cp rnetmgr.service /etc/systemd/system/
sudo systemctl daemon-reload
```

3. Enable and start:

```sh
sudo systemctl enable rnetmgr
sudo systemctl start rnetmgr
```

To use dnsmasq, edit `rnetmgr.service` and add `-n` to the `ExecStart` line via the `OPTARG` environment variable.

## Runtime dependencies

| Program | Required for |
|---------|-------------|
| `dhcpcd` | DHCP client mode |
| `kea-dhcp4` | DHCP server mode (default backend) |
| `dnsmasq` | DHCP server mode (alternative backend) |
| `iptables` | NAT routing (`routeif` option) |

## License

MIT OR Apache-2.0
