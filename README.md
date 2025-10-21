# babysniff

A zero-dependency network sniffer, written from scratch, that supports emulated and native cBPF. Runs on Linux, BSD, macOS, and Windows. Currently supports ETH, ARP, IP, ICMP, TCP, UDP, DNS.

It's a toy tool that I created to learn more about network protocols. It's still rudimentary when compared to tcpdump or wireshark.

> [!WARNING]
> This repo is a work in progress!

## Supported protocols

| Layer 2  | Layer 3  | Layer 4  | Layer 7  |
|----------|----------|----------|----------|
| ETH      | ICMP     | TCP      | DNS      |
| ARP      | IP       | UDP      |          |

**Notes**:
1. Support for EDNS0/DNSSEC is WIP


## BPF (Berkeley Packet Filter) support

It supports _native_ and _emulated_ BPF filtering capabilities **without depending on any library**. This enables tcpdump-style packet filtering.

### Features

- **BPF virtual machine**: Our BPF VM implementation supports the full BPF instruction set
- **Filters tcpdump-style**: Familiar filtering syntax (**Note**: Only basic expressions are supported)
- **Smart protocol auto-enabling**: BPF filters automatically enable corresponding protocol display filters (**Note**: Display filters will be removed in the future)
- **Hostname resolution**: Support for host filters with automatic DNS resolution
- **Zero external dependencies**: We implemented everything from scratch to avoid any dependencies! Sorry _pcap_ :-)

### Supported filter types

- **Protocol filters**: `arp`, `ip`, `ipv6`, `tcp`, `udp`, `icmp`, `dns`
- **Host filters**: `host 192.168.1.1` (matches source or destination)
- **Port filters**: `port 80` (matches source or destination TCP/UDP ports)

## How to build

### Linux/macOS/BSD
```shell
cmake . && make
```

### Windows
See [Build on Windows](docs/build-on-windows.md) for detailed Windows build instructions.

## How to use

The superuser privilege is necessary because Linux and BSD systems require elevated privileges to enable the promiscuous mode in network interfaces.

### Usage examples

```shell
# Capture all IP traffic (default when no filter specified)
sudo ./babysniff -i eth0

# Filter TCP traffic only
sudo ./babysniff -i eth0 "tcp"

# Filter UDP traffic only
sudo ./babysniff -i eth0 "udp"

# Filter traffic to/from a specific host
sudo ./babysniff -i eth0 "host 192.168.1.1"

# Filter traffic on port 80
sudo ./babysniff -i eth0 "port 80"

# Filter DNS traffic
sudo ./babysniff -i eth0 "dns"

# Combine with protocol display filters for control
sudo ./babysniff -i eth0 -d tcp,ip,eth "tcp"
```

### Command line usage

```
babysniff [OPTIONS] [expression]
```

**Arguments:**
- `[expression]`: BPF filter expression (tcpdump-style) - **optional**
  - If not provided, defaults to `"ip"` (captures all IP traffic)
  - Examples: `"tcp"`, `"host 192.168.1.1"`, `"port 80"`

**Options:**
- `-b, --background`: Run in background (daemonize)
- `-i, --interface`: Specify network interface to monitor
- `-d, --display-filters`: Specify a list of display filters separated by comma (arp, dns, dns-data eth, icmp, ip, tcp, tcp-data, udp, udp-data)
- `-E, --bpf-emulator`: Use emulated BPF instead of native BPF
- `-l, --loglevel`: Set logging verbosity level
- `-h, --help`: Display help and exit

## Limitations

Due to Microsoft's security restrictions in Windows XP SP2 and later, we cannot capture the Ethernet (data link layer) part of packets on Windows using raw sockets.

**Windows raw sockets are limited**: They operate at the Network Layer (Layer 3) with `SOCK_RAW` and `SIO_RCVALL`, capturing packets starting from the IP header, not the Data Link Layer (Layer 2) where Ethernet headers reside.

**Impact**: On Windows, babysniff can capture and analyze IP, TCP, UDP, ICMP, and DNS protocols correctly, but Ethernet-level information (MAC addresses, VLAN tags, etc) is not available.

**Alternative**: Full Ethernet capture could be achieved by providing a kernel driver like WinPcap/Npcap have, but this is beyond the current scope of this zero-dependency project.

## Screenshots

![Screenshot 1](/docs/screenshots/screenshot1.png?raw=true "screenshot 1")
