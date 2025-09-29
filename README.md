# babysniff

A simple network sniffer for Linux and macOS written from scratch without any libraries.

It's a toy tool that I created to learn more about network protocols. It's rudimentary when compared to tcpdump or wireshark.

## Supported protocols

| Layer 2  | Layer 3  | Layer 4  | Layer 7  |
|----------|----------|----------|----------|
| ETH      | ICMP     | TCP      | DNS      |
| ARP      | IP       | UDP      | Cell     |

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

```shell
cmake . && make
```

## How to use

The superuser privilege is necessary because Linux and BSD systems require elevated privileges to enable the promiscuous mode in network interfaces.

### Usage examples

```shell
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
babysniff [OPTIONS] <expression>
```

**Arguments:**
- `<expression>`: BPF filter expression (tcpdump-style) - **required**

**Options:**
- `-b, --background`: Run in background (daemonize)
- `-i, --interface`: Specify network interface to monitor
- `-d, --display-filters`: Specify a list of display filters separated by comma (arp, dns, dns-data eth, icmp, ip, tcp, tcp-data, udp, udp-data)
- `-E, --bpf-emulator`: Use emulated BPF instead of native BPF
- `-l, --loglevel`: Set logging verbosity level
- `-h, --help`: Display help and exit

## Screenshots

![Screenshot 1](/docs/screenshots/screenshot1.png?raw=true "screenshot 1")
