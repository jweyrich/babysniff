# babysniff

A simple network sniffer for Linux and macOS written from scratch without any libraries.

It's a toy tool that I created to learn more about network protocols. It's rudimentary when compared to tcpdump or wireshark.

## Supported protocols

Layer 2
- ETH
- ARP

Layer 3
- ICMP
- IP

Layer 4
- TCP
- UDP

Layer 7
- DNS (wip on EDNS0)

## How to build

```shell
cmake .
make
```

## How to use

The superuser privilege is necessary because Linux and BSD systems require elevated privileges to enable the promiscuous mode in network interfaces.

```shell
sudo ./babysniff -f -i eth0 -F arp,icmp,tcp,udp
```

## Screenshots

![Screenshot 1](/docs/screenshots/screenshot1.png?raw=true "screenshot 1")