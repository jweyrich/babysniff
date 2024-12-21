#pragma once

#include <stdlib.h>
#include "common.h"
#include "types.h"
#include "config.h"

//
// Parsing
//
int sniff_packet_fromwire(const byte *packet, size_t length, int protocol, const config_t *config);
int sniff_eth_fromwire(const byte *packet, size_t length, const config_t *config);
int sniff_arp_fromwire(const byte *packet, size_t length, const config_t *config);
int sniff_dns_fromwire(const byte *packet, size_t length, const config_t *config);
int sniff_icmp_fromwire(const byte *packet, size_t length, const config_t *config);
int sniff_ip_fromwire(const byte *packet, size_t length, const config_t *config);
int sniff_tcp_fromwire(const byte *packet, size_t length, const config_t *config);
int sniff_udp_fromwire(const byte *packet, size_t length, const config_t *config);
