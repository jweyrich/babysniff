#pragma once

#include <stdlib.h>
#include "common.h"
#include "types.h"

//
// Parsing
//
int sniff_packet_fromwire(const byte *packet, size_t length, int protocol);
int sniff_eth_fromwire(const byte *packet, size_t length);
int sniff_arp_fromwire(const byte *packet, size_t length);
int sniff_dns_fromwire(const byte *packet, size_t length);
int sniff_icmp_fromwire(const byte *packet, size_t length);
int sniff_ip_fromwire(const byte *packet, size_t length);
int sniff_tcp_fromwire(const byte *packet, size_t length);
int sniff_udp_fromwire(const byte *packet, size_t length);
