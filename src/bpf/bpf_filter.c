#ifndef _DEFAULT_SOURCE
#   define _DEFAULT_SOURCE
#endif

#include "bpf/bpf_filter.h"

#include "bpf/bpf_vm.h"
#include "compat/network_compat.h"
#include "compat/string_compat.h"
#include "system.h"

#include <ctype.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef OS_WINDOWS
#   include <strings.h> // Windows doesn't have strings.h
#   include <netinet/ip.h>
#   include <netdb.h>
#   include <net/ethernet.h> // For ETHERTYPE_IP
#else
// Windows doesn't have strings.h
#   define strcasecmp _stricmp
#endif

#include <stddef.h> // for offsetof

#ifndef OS_WINDOWS
#	include <netinet/ip.h>      // for struct ip
#	include <netinet/tcp.h>     // for struct tcphdr
#	include <netinet/udp.h>     // for struct udphdr
#	include <net/ethernet.h>    // for ETH_HLEN
#	include <netdb.h>
#endif

// Global datalink type variable with platform-appropriate default
#ifdef OS_WINDOWS
datalink_type_t g_bpf_datalink_type = DATALINK_RAW_IP;
#else
datalink_type_t g_bpf_datalink_type = DATALINK_ETHERNET;
#endif

// Function to set the global datalink type
void bpf_set_datalink_type(datalink_type_t datalink_type) {
    g_bpf_datalink_type = datalink_type;
}

// Function to get the current global datalink type
datalink_type_t bpf_get_datalink_type(void) {
    return g_bpf_datalink_type;
}

// Auto-detect datalink type from packet data
static datalink_type_t detect_datalink_type(const uint8_t *packet, size_t len) {
    if (len < 20) { // size of minimum IP header
        return DATALINK_ETHERNET; // Default fallback
    }

    // Check if this looks like an IP packet at offset 0
    uint8_t version = (packet[0] >> 4) & 0x0F;
    if (version == 4 || version == 6) {
        // Looks like IP header at start - probably raw IP
        return DATALINK_RAW_IP;
    }

    // Check if this looks like Ethernet + IP at offset 14
    if (len >= 14 + 20) {
        version = (packet[14] >> 4) & 0x0F;
        if (version == 4 || version == 6) {
            // Check EtherType too
            uint16_t ethertype = (packet[12] << 8) | packet[13];
            if (ethertype == ETHERTYPE_IP || ethertype == ETHERTYPE_IPV6) {
                return DATALINK_ETHERNET;
            }
        }
    }

    // Default to Ethernet
    return DATALINK_ETHERNET;
}

// Offset definitions based on datalink type
typedef struct {
    int ethertype_offset;     // Offset to EtherType field (-1 if not available)
    int ip_header_offset;     // Offset to start of IP header
    int ip_version_offset;    // Offset to IP version/IHL byte
    int ip_proto_offset;      // Offset to IP protocol field
    int ip_src_offset;        // Offset to IP source address
    int ip_dst_offset;        // Offset to IP destination address
    int tcp_sport_offset;     // Offset to TCP source port
    int tcp_dport_offset;     // Offset to TCP destination port
    int udp_sport_offset;     // Offset to UDP source port
    int udp_dport_offset;     // Offset to UDP destination port
} bpf_offsets_t;

// Get offsets based on datalink type
static bpf_offsets_t get_bpf_offsets(datalink_type_t datalink) {
    bpf_offsets_t offsets = {0};
    int ip_hdr_offset = 0;

    switch (datalink) {
        case DATALINK_ETHERNET:
            ip_hdr_offset = (int)sizeof(struct ether_header); // 14 = Right after Ethernet header
            offsets.ethertype_offset = offsetof(struct ether_header, ether_type); // 12
            offsets.ip_header_offset = ip_hdr_offset; // 14
            offsets.ip_version_offset = ip_hdr_offset; // 14 (eth)
            offsets.ip_proto_offset = ip_hdr_offset + offsetof(struct ip, ip_p); // 23 = 14 (eth) + 9 (IP protocol field)
            offsets.ip_src_offset = ip_hdr_offset + offsetof(struct ip, ip_src); // 26 = 14 (eth) + 12 (IP src)
            offsets.ip_dst_offset = ip_hdr_offset + offsetof(struct ip, ip_dst); // 30 = 14 (eth) + 16 (IP dst)
            offsets.tcp_sport_offset = ip_hdr_offset + sizeof(struct ip) + offsetof(struct tcphdr, th_sport); // 34 = 14 (eth) + 20 (IP hdr) + 0 (TCP sport)
            offsets.tcp_dport_offset = ip_hdr_offset + sizeof(struct ip) + offsetof(struct tcphdr, th_dport); // 36 = 14 (eth) + 20 (IP hdr) + 2 (TCP dport)
            offsets.udp_sport_offset = ip_hdr_offset + sizeof(struct ip) + offsetof(struct udphdr, uh_sport); // 34 = 14 (eth) + 20 (IP hdr) + 0 (UDP sport)
            offsets.udp_dport_offset = ip_hdr_offset + sizeof(struct ip) + offsetof(struct udphdr, uh_dport); // 36 = 14 (eth) + 20 (IP hdr) + 2 (UDP dport)
            break;

        case DATALINK_RAW_IP:
            offsets.ethertype_offset = -1; // Not available
            offsets.ip_header_offset = ip_hdr_offset; // 0
            offsets.ip_version_offset = ip_hdr_offset; // 0
            offsets.ip_proto_offset = offsetof(struct ip, ip_p); // 9 = IP protocol field
            offsets.ip_src_offset = offsetof(struct ip, ip_src); // 12 = IP src
            offsets.ip_dst_offset = offsetof(struct ip, ip_dst); // 16 = IP dst
            offsets.tcp_sport_offset = sizeof(struct ip) + offsetof(struct tcphdr, th_sport); // 20 = 20 (IP hdr) + 0 (TCP sport)
            offsets.tcp_dport_offset = sizeof(struct ip) + offsetof(struct tcphdr, th_dport); // 22 = 20 (IP hdr) + 2 (TCP dport)
            offsets.udp_sport_offset = sizeof(struct ip) + offsetof(struct udphdr, uh_sport); // 20 = 20 (IP hdr) + 0 (UDP sport)
            offsets.udp_dport_offset = sizeof(struct ip) + offsetof(struct udphdr, uh_dport); // 22 = 20 (IP hdr) + 2 (UDP dport)
            break;

        default:
            // Default to Ethernet for backward compatibility
            return get_bpf_offsets(DATALINK_ETHERNET);
    }

    return offsets;
}

// Helper function to resolve hostname to IP address
static int resolve_hostname(const char *hostname, struct in_addr *addr) {
    const int family = AF_INET; // IPv4 only because we don't yet support IPv6

    // Try to parse as IPv4 address first using inet_pton (cross-platform)
    if (inet_pton(family, hostname, addr) == 1) {
        return 0;
    }

    // Try to resolve hostname using getaddrinfo
    struct addrinfo hints, *result;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = family;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(hostname, NULL, &hints, &result) == 0) {
        struct sockaddr_in *sockaddr_ipv4 = (struct sockaddr_in *)result->ai_addr;
        *addr = sockaddr_ipv4->sin_addr;
        freeaddrinfo(result);
        return 0;
    }

    return -1;
}

// Helper function to allocate and copy BPF instructions
int bpf_set_instructions(bpf_program_t *program, const struct bpf_insn *instns, size_t total_size) {
    if (program->bf_insns) {
        // If there are existing instructions, free them first.
        bpf_free_program(program);
    }
    const size_t count = total_size / sizeof(struct bpf_insn);
    if (count > UINT_MAX) {
        // Catch potential overflow in systems where `unsigned int` is smaller than `size_t`.
        // In 32-bit systems, size_t is usually 32 bits, so this condition is always false.
        // In 64-bit systems, size_t is usually 64 bits, so this condition can be true.
        return -1; // Count exceeds unsigned int range
    }
    program->bf_len = (unsigned int)count;
    program->bf_insns = calloc(program->bf_len, sizeof(struct bpf_insn));
    if (!program->bf_insns) {
        return -1;
    }
    memcpy(program->bf_insns, instns, total_size);
    return 0;
}

// Create a simple host filter (matches src or dst IP)
int bpf_create_host_filter_ex(const char *host, bpf_program_t *program, datalink_type_t datalink) {
    struct in_addr addr;
    bpf_offsets_t offsets = get_bpf_offsets(datalink);

    if (resolve_hostname(host, &addr) < 0) {
        return -1;
    }

    uint32_t host_ip = ntohl(addr.s_addr);

    if (datalink == DATALINK_ETHERNET) {
        // For Ethernet, check EtherType and then IP addresses
        const struct bpf_insn instns[] = {
            BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),                    // 0: Load EtherType
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IP, 0, 5),   // 1: If not IP, jump 5 to reject (7)
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsets.ip_src_offset), // 2: Load src IP
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, host_ip, 2, 0),        // 3: If src IP matches, jump 2 to accept (6)
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsets.ip_dst_offset), // 4: Load dst IP
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, host_ip, 0, 1),        // 5: If dst IP matches, accept (next), else jump 1 to reject (7)
            BPF_STMT(BPF_RET | BPF_K, 0xffff),                         // 6: Accept
            BPF_STMT(BPF_RET | BPF_K, 0),                              // 7: Reject
        };
        return bpf_set_instructions(program, instns, sizeof(instns));
    } else {
        // Without Ethernet header, just check IP addresses
        const struct bpf_insn instns[] = {
            BPF_STMT(BPF_LD | BPF_B | BPF_ABS, offsets.ip_version_offset), // 0: Load IP version/IHL byte
            BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xF0),                     // 1: Mask to get only version bits (TODO: depends on endianess)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x40, 0, 5),               // 2: Check for IPv4 (version 4 << 4), jump 6 to reject if not (TODO: depends on endianess)
            // Same code from here on...
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsets.ip_src_offset),     // 3: Load src IP
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, host_ip, 2, 0),            // 4: If src IP matches, jump 2 to accept (7)
            BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsets.ip_dst_offset),     // 5: Load dst IP
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, host_ip, 0, 1),            // 6: If dst IP matches, accept (next), else jump 1 to reject (8)
            BPF_STMT(BPF_RET | BPF_K, 0xffff),                             // 7: Accept
            BPF_STMT(BPF_RET | BPF_K, 0),                                  // 8: Reject
        };
        return bpf_set_instructions(program, instns, sizeof(instns));
    }
}

// Create a port filter (matches src or dst port for SCTP/TCP/UDP)
int bpf_create_port_filter_ex(uint16_t port, bpf_program_t *program, datalink_type_t datalink) {
    bpf_offsets_t offsets = get_bpf_offsets(datalink);

    if (datalink == DATALINK_ETHERNET) {
        // With Ethernet header
        const struct bpf_insn instns[] = {
            BPF_STMT(BPF_LD | BPF_H | BPF_ABS, offsets.ethertype_offset),      // 0: Load EtherType
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IP, 0, 8),           // 1: If not IPv4, jump 8 to reject (12)
            BPF_STMT(BPF_LD | BPF_B | BPF_ABS, offsets.ip_proto_offset),       // 2: Load IP protocol
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 2, 0),            // 3: If TCP, jump 2 to header length load (6)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 1, 0),            // 4: If UDP, jump 1 to header length load (6)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_SCTP, 0, 4),           // 5: If not SCTP, jump 4 to reject (12)
            BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, offsets.ip_header_offset),     // 6: Load IP header length
            BPF_STMT(BPF_LD | BPF_H | BPF_IND, offsets.ip_header_offset),      // 7: Load src port
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, port, 2, 0),                   // 8: If src port matches, jump 2 to accept (11)
            BPF_STMT(BPF_LD | BPF_H | BPF_IND, offsets.ip_header_offset + 2),  // 9: Load dst port
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, port, 0, 1),                   // 10: If dst port matches, accept (next), else jump 1 to reject (12)
            BPF_STMT(BPF_RET | BPF_K, 0xffff),                                 // 11: Accept
            BPF_STMT(BPF_RET | BPF_K, 0),                                      // 12: Reject
        };
        return bpf_set_instructions(program, instns, sizeof(instns));
    } else {
        // Without Ethernet header -- assumes standard 20-byte IP header for simplicity
        const struct bpf_insn instns[] = {
            BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0),                             // 0: Load IP version/IHL byte
            BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xF0),                         // 1: Mask to get only version bits (TODO: depends on endianess)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x40, 0, 9),                   // 2: Check for IPv4, jump 9 to reject (12) if not (TODO: depends on endianess)
            BPF_STMT(BPF_LD | BPF_B | BPF_ABS, offsets.ip_proto_offset),       // 3: Load IP protocol
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 2, 0),            // 4: If TCP, jump 2 to port check (7)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 1, 0),            // 5: If UDP, jump 1 to port check (7)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_SCTP, 0, 4),           // 6: If not SCTP, jump 4 to reject (12)
            BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 20),                            // 7: Load src port (assume 20-byte IP header)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, port, 2, 0),                   // 8: If src port matches, jump 2 to accept (11)
            BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 22),                            // 9: Load dst port
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, port, 0, 1),                   // 10: If dst port matches, accept (next), else jump 1 to reject (12)
            BPF_STMT(BPF_RET | BPF_K, 0xffff),                                 // 11: Accept
            BPF_STMT(BPF_RET | BPF_K, 0),                                      // 12: Reject
        };
        return bpf_set_instructions(program, instns, sizeof(instns));
    }
}

// Create a protocol filter (ARP, IP, TCP, UDP, ICMP, DNS, or numeric)
int bpf_create_protocol_filter_ex(const char *protocol, bpf_program_t *program, datalink_type_t datalink) {
    bpf_offsets_t offsets = get_bpf_offsets(datalink);

    if (strcasecmp(protocol, "arp") == 0) {
        if (datalink == DATALINK_ETHERNET) {
            // For Ethernet, "arp" protocol means EtherType = ETHERTYPE_ARP
            const struct bpf_insn instns[] = {
                BPF_STMT(BPF_LD | BPF_H | BPF_ABS, offsets.ethertype_offset),      // 0: Load EtherType
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_ARP, 0, 1),          // 1: If not ARP, jump 1 to reject (3)
                BPF_STMT(BPF_RET | BPF_K, 0xffff),                                 // 2: Accept
                BPF_STMT(BPF_RET | BPF_K, 0),                                      // 3: Reject
            };
            return bpf_set_instructions(program, instns, sizeof(instns));
        } else {
            // Ethernet header is required for ARP filtering
            return -1;
        }
    } else if (strcasecmp(protocol, "ip") == 0) {
        // Right now we handle only IPv4. We may want to support IPv6 later.
        if (datalink == DATALINK_ETHERNET) {
            // For Ethernet, "ip" protocol means EtherType = ETHERTYPE_IP
            const struct bpf_insn instns[] = {
                BPF_STMT(BPF_LD | BPF_H | BPF_ABS, offsets.ethertype_offset),      // 0: Load EtherType
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IP, 0, 1),           // 1: If not IP, jump 1 to reject (3)
                BPF_STMT(BPF_RET | BPF_K, 0xffff),                                 // 2: Accept
                BPF_STMT(BPF_RET | BPF_K, 0),                                      // 3: Reject
            };
            return bpf_set_instructions(program, instns, sizeof(instns));
        } else {
            // For raw IP, just check that it's IPv4 by looking at the version field
            const struct bpf_insn instns[] = {
                BPF_STMT(BPF_LD | BPF_B | BPF_ABS, offsets.ip_version_offset), // 0: Load IP version/IHL byte
                BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xF0),                     // 1: Mask to get only version bits (TODO: depends on endianess)
                BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x40, 0, 1),               // 2: If not IPv4, jump 1 to reject (4) (TODO: depends on endianess)
                BPF_STMT(BPF_RET | BPF_K, 0xffff),                             // 3: Accept
                BPF_STMT(BPF_RET | BPF_K, 0),                                  // 4: Reject
            };
            return bpf_set_instructions(program, instns, sizeof(instns));
        }
    } else if (strcasecmp(protocol, "dns") == 0) {
        // Assume port 53
        return bpf_create_port_filter_ex(53, program, datalink);
    }

    // Handle IP protocol types (layer 3/4)
    uint8_t proto_num;
    if (strcasecmp(protocol, "sctp") == 0) {
        proto_num = IPPROTO_SCTP;
    } else if (strcasecmp(protocol, "tcp") == 0) {
        proto_num = IPPROTO_TCP;
    } else if (strcasecmp(protocol, "udp") == 0) {
        proto_num = IPPROTO_UDP;
    } else if (strcasecmp(protocol, "icmp") == 0) {
        proto_num = IPPROTO_ICMP;
    } else {
        // Try to parse as number
        char *endptr;
        long val = strtol(protocol, &endptr, 10);
        if (*endptr != '\0' || val < 0 || val > 255) {
            return -1;
        }
        proto_num = (uint8_t)val;
    }

    if (datalink == DATALINK_ETHERNET) {
        // For Ethernet, check EtherType and then protocol
        const struct bpf_insn instns[] = {
            BPF_STMT(BPF_LD | BPF_H | BPF_ABS, offsets.ethertype_offset),      // 0: Load EtherType
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IP, 0, 3),           // 1: If not IPv4, jump 3 to reject (5)
            BPF_STMT(BPF_LD | BPF_B | BPF_ABS, offsets.ip_proto_offset),       // 2: Load IP protocol field
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, proto_num, 0, 1),              // 3: If protocol doesn't match, jump 1 to reject (5)
            BPF_STMT(BPF_RET | BPF_K, 0xffff),                                 // 4: Accept
            BPF_STMT(BPF_RET | BPF_K, 0),                                      // 5: Reject
        };
        return bpf_set_instructions(program, instns, sizeof(instns));
    } else {
        // For raw IP, just check protocol
        const struct bpf_insn instns[] = {
            BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 0),                         // 0: Load IP version/IHL byte
            BPF_STMT(BPF_ALU | BPF_AND | BPF_K, 0xF0),                     // 1: Mask to get only version bits (TODO: depends on endianess)
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 0x40, 0, 4),               // 2: Check for IPv4, jump 4 to reject (6) if not (TODO: depends on endianess)
            BPF_STMT(BPF_LD | BPF_B | BPF_ABS, offsets.ip_proto_offset),   // 3: Load IP protocol field
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, proto_num, 0, 1),          // 4: Jump 1 to reject (6) if protocol doesn't match
            BPF_STMT(BPF_RET | BPF_K, 0xffff),                             // 5: Accept
            BPF_STMT(BPF_RET | BPF_K, 0),                                  // 6: Reject
        };
        return bpf_set_instructions(program, instns, sizeof(instns));
    }
}

// Backward compatibility wrappers that use global datalink type
int bpf_create_host_filter(const char *host, bpf_program_t *program) {
    return bpf_create_host_filter_ex(host, program, g_bpf_datalink_type);
}

int bpf_create_port_filter(uint16_t port, bpf_program_t *program) {
    return bpf_create_port_filter_ex(port, program, g_bpf_datalink_type);
}

int bpf_create_protocol_filter(const char *protocol, bpf_program_t *program) {
    return bpf_create_protocol_filter_ex(protocol, program, g_bpf_datalink_type);
}

int bpf_create_empty_filter(bpf_program_t *program) {
    const struct bpf_insn instns[] = {
        BPF_STMT(BPF_RET | BPF_K, 0xffff), // 0: Accept all packets
    };
    return bpf_set_instructions(program, instns, sizeof(instns));
}

void bpf_free_program(bpf_program_t *program) {
    if (!program) {
        return;
    }
    free(program->bf_insns);
}

// Simple tokenizer for filter expressions
typedef struct {
    char *tokens[64];
    size_t count;
} token_list_t;

static void tokenize(const char *expression, token_list_t *tokens) {
    char *expr_copy = strdup(expression);
    char *token;
    char *saveptr;

    tokens->count = 0;
    token = strtok_r(expr_copy, " \t\n", &saveptr);

    while (token && tokens->count < 64) {
        tokens->tokens[tokens->count] = strdup(token);
        tokens->count++;
        token = strtok_r(NULL, " \t\n", &saveptr);
    }

    free(expr_copy);
}

static void free_token_list(token_list_t *tokens) {
    for (size_t i = 0; i < tokens->count; i++) {
        free(tokens->tokens[i]);
    }
    tokens->count = 0;
}

// Simple filter expression parser
// Supports basic expressions like:
// - host 192.168.1.1
// - port 80
// - tcp
int bpf_compile_filter_ex(const char *filter_string, bpf_program_t *program, datalink_type_t datalink) {
    if (!program) {
        return -1;
    }

    if (!filter_string || strlen(filter_string) == 0) {
        return bpf_create_empty_filter(program);
    }

    token_list_t token_list;
    tokenize(filter_string, &token_list);

    if (token_list.count == 0) {
        free_token_list(&token_list);
        return -1;
    }

    int result = -1;

    // Handle simple filter expressions
    if (token_list.count == 2) {
        if (strcasecmp(token_list.tokens[0], "host") == 0) {
            result = bpf_create_host_filter_ex(token_list.tokens[1], program, datalink);
        } else if (strcasecmp(token_list.tokens[0], "port") == 0) {
            char *endptr;
            long port = strtol(token_list.tokens[1], &endptr, 10);
            if (*endptr == '\0' && port >= 0 && port <= 65535) {
                result = bpf_create_port_filter_ex((uint16_t)port, program, datalink);
            }
        }
    } else if (token_list.count == 1) {
        // Single protocol filter
        result = bpf_create_protocol_filter_ex(token_list.tokens[0], program, datalink);
    }

    free_token_list(&token_list);
    return result;
}

int bpf_compile_filter(const char *filter_string, bpf_program_t *program) {
    return bpf_compile_filter_ex(filter_string, program, g_bpf_datalink_type);
}

// Auto-detecting wrapper that determines datalink type from a sample packet
int bpf_compile_filter_auto(const char *filter_string, bpf_program_t *program,
                            const uint8_t *sample_packet, size_t packet_len)
{
    datalink_type_t datalink = detect_datalink_type(sample_packet, packet_len);
    return bpf_compile_filter_ex(filter_string, program, datalink);
}
