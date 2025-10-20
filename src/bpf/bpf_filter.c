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

// Helper macros for offset calculations
#define ETHER_HDR_SIZE   sizeof(struct ether_header)  // 14 bytes
#define IP_HDR_SIZE      sizeof(struct ip)             // 20 bytes (minimum)
#define TCP_HDR_SIZE     sizeof(struct tcphdr)         // 20 bytes (minimum)
#define UDP_HDR_SIZE     sizeof(struct udphdr)         // 8 bytes

// Get offsets based on datalink type
static bpf_offsets_t get_bpf_offsets(datalink_type_t datalink) {
    bpf_offsets_t offsets = {0};

    switch (datalink) {
        case DATALINK_ETHERNET: {
            // [ETH_HDR][IP_HDR][TCP_HDR/UDP_HDR][DATA]
            const int eth_size = ETHER_HDR_SIZE;
            const int ip_start = eth_size;
            const int transport_start = ip_start + IP_HDR_SIZE;

            offsets.ethertype_offset = offsetof(struct ether_header, ether_type);
            offsets.ip_header_offset = ip_start;
            offsets.ip_version_offset = ip_start;
            offsets.ip_proto_offset = ip_start + offsetof(struct ip, ip_p);
            offsets.ip_src_offset = ip_start + offsetof(struct ip, ip_src);
            offsets.ip_dst_offset = ip_start + offsetof(struct ip, ip_dst);
            offsets.tcp_sport_offset = transport_start + offsetof(struct tcphdr, th_sport);
            offsets.tcp_dport_offset = transport_start + offsetof(struct tcphdr, th_dport);
            offsets.udp_sport_offset = transport_start + offsetof(struct udphdr, uh_sport);
            offsets.udp_dport_offset = transport_start + offsetof(struct udphdr, uh_dport);
            break;
        }

        case DATALINK_RAW_IP: {
            // [IP_HDR][TCP_HDR/UDP_HDR][DATA]
            const int ip_start = 0;
            const int transport_start = IP_HDR_SIZE;

            offsets.ethertype_offset = -1;  // Not available in raw IP
            offsets.ip_header_offset = ip_start;
            offsets.ip_version_offset = ip_start;
            offsets.ip_proto_offset = offsetof(struct ip, ip_p);
            offsets.ip_src_offset = offsetof(struct ip, ip_src);
            offsets.ip_dst_offset = offsetof(struct ip, ip_dst);
            offsets.tcp_sport_offset = transport_start + offsetof(struct tcphdr, th_sport);
            offsets.tcp_dport_offset = transport_start + offsetof(struct tcphdr, th_dport);
            offsets.udp_sport_offset = transport_start + offsetof(struct udphdr, uh_sport);
            offsets.udp_dport_offset = transport_start + offsetof(struct udphdr, uh_dport);
            break;
        }

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

// BPF instruction builder for cleaner filter generation
typedef struct {
    struct bpf_insn instructions[32];  // Max reasonable size for a filter
    size_t count;
} bpf_instruction_builder_t;

static void bpf_builder_init(bpf_instruction_builder_t *builder) {
    builder->count = 0;
}

static void bpf_builder_add(bpf_instruction_builder_t *builder, struct bpf_insn insn) {
    if (builder->count < 32) {
        builder->instructions[builder->count++] = insn;
    }
}

static void bpf_builder_add_load_abs(bpf_instruction_builder_t *builder, int size, int offset) {
    uint16_t code = BPF_LD | BPF_ABS;
    switch (size) {
        case 1: code |= BPF_B; break;  // byte
        case 2: code |= BPF_H; break;  // half-word
        case 4: code |= BPF_W; break;  // word
        default:
            // Invalid size
            fprintf(stderr, "bpf_builder_add_load_abs: Invalid size %d\n", size);
            abort();
    }
    bpf_builder_add(builder, (struct bpf_insn)BPF_STMT(code, offset));
}

static void bpf_builder_add_jump_eq(bpf_instruction_builder_t *builder, uint32_t value, int jt, int jf) {
    bpf_builder_add(builder, (struct bpf_insn)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, value, jt, jf));
}

static void bpf_builder_add_alu_and(bpf_instruction_builder_t *builder, uint32_t mask) {
    bpf_builder_add(builder, (struct bpf_insn)BPF_STMT(BPF_ALU | BPF_AND | BPF_K, mask));
}

static void bpf_builder_add_return(bpf_instruction_builder_t *builder, uint32_t value) {
    bpf_builder_add(builder, (struct bpf_insn)BPF_STMT(BPF_RET | BPF_K, value));
}

static void bpf_builder_add_load_x_msh(bpf_instruction_builder_t *builder, int offset) {
    bpf_builder_add(builder, (struct bpf_insn)BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, offset));
}

static void bpf_builder_add_load_ind(bpf_instruction_builder_t *builder, int size, int offset) {
    uint16_t code = BPF_LD | BPF_IND;
    switch (size) {
        case 2: code |= BPF_H; break;  // half-word
        case 4: code |= BPF_W; break;  // word
        default: return; // Invalid size
    }
    bpf_builder_add(builder, (struct bpf_insn)BPF_STMT(code, offset));
}

static int bpf_builder_finalize(bpf_instruction_builder_t *builder, bpf_program_t *program) {
    return bpf_set_instructions(program, builder->instructions, builder->count * sizeof(struct bpf_insn));
}

// Protocol information lookup table
typedef struct {
	const char *proto_name;
	uint8_t ip_protocol;
	uint16_t default_port;
	bool requires_ethernet;
} protocol_info_t;

static const protocol_info_t protocol_table[] = {
	{ "tcp",  IPPROTO_TCP,  0,  false },
	{ "udp",  IPPROTO_UDP,  0,  false },
	{ "icmp", IPPROTO_ICMP, 0,  false },
	{ "sctp", IPPROTO_SCTP, 0,  false },
	{ "arp",  0,            0,  true  },
	{ "ip",   0,            0,  false },
	{ "dns",  IPPROTO_UDP,  53, false },
	{ NULL,   0,            0,  false }
};

static const protocol_info_t* find_protocol_info(const char *proto_name) {
    for (const protocol_info_t *p = protocol_table; p->proto_name != NULL; p++) {
        if (strcasecmp(proto_name, p->proto_name) == 0) {
            return p;
        }
    }
    return NULL;
}

// Common BPF instruction sequence builders
static void build_ethernet_header_check(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint16_t ethertype, int reject_offset) {
    bpf_builder_add_load_abs(builder, 2, offsets.ethertype_offset);  // Load EtherType
    bpf_builder_add_jump_eq(builder, ethertype, 0, reject_offset);   // If not matching ethertype, jump to reject
}

static void build_ipv4_version_check(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, int reject_offset) {
    bpf_builder_add_load_abs(builder, 1, offsets.ip_version_offset); // Load IP version/IHL byte
    bpf_builder_add_alu_and(builder, 0xF0);                          // Mask to get only version bits (TODO: depends on endianness?)
    bpf_builder_add_jump_eq(builder, 0x40, 0, reject_offset);        // Check for IPv4, jump to reject if not (TODO: depends on endianness?)
}

static void build_ip_address_match(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint32_t ip_addr) {
    bpf_builder_add_load_abs(builder, 4, offsets.ip_src_offset);     // Load src IP
    bpf_builder_add_jump_eq(builder, ip_addr, 2, 0);                 // If src IP matches, jump 2 to accept
    bpf_builder_add_load_abs(builder, 4, offsets.ip_dst_offset);     // Load dst IP
    bpf_builder_add_jump_eq(builder, ip_addr, 0, 1);                 // If dst IP matches, accept, else jump 1 to reject
}

static void build_protocol_check(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint8_t protocol, int reject_offset) {
    bpf_builder_add_load_abs(builder, 1, offsets.ip_proto_offset);   // Load IP protocol
    bpf_builder_add_jump_eq(builder, protocol, 0, reject_offset);    // If protocol doesn't match, jump to reject
}

static void build_port_match_simple(bpf_instruction_builder_t *builder, uint16_t port, int src_offset, int dst_offset) {
    bpf_builder_add_load_abs(builder, 2, src_offset);                // Load src port
    bpf_builder_add_jump_eq(builder, port, 2, 0);                    // If src port matches, jump 2 to accept
    bpf_builder_add_load_abs(builder, 2, dst_offset);                // Load dst port
    bpf_builder_add_jump_eq(builder, port, 0, 1);                    // If dst port matches, accept, else jump 1 to reject
}

static void build_port_match_with_protocols(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint16_t port, int reject_offset) {
    // Check for TCP, UDP, or SCTP
    bpf_builder_add_load_abs(builder, 1, offsets.ip_proto_offset);   // Load IP protocol
    bpf_builder_add_jump_eq(builder, IPPROTO_TCP, 2, 0);             // If TCP, jump 2
    bpf_builder_add_jump_eq(builder, IPPROTO_UDP, 1, 0);             // If UDP, jump 1
    bpf_builder_add_jump_eq(builder, IPPROTO_SCTP, 0, reject_offset - 4); // If not SCTP, jump to reject

    // For variable IP header length (proper implementation)
    bpf_builder_add_load_x_msh(builder, offsets.ip_header_offset);   // Load IP header length into X
    bpf_builder_add_load_ind(builder, 2, offsets.ip_header_offset);  // Load src port using X+offset
    bpf_builder_add_jump_eq(builder, port, 2, 0);                    // If src port matches, jump 2 to accept
    bpf_builder_add_load_ind(builder, 2, offsets.ip_header_offset + 2); // Load dst port using X+offset
    bpf_builder_add_jump_eq(builder, port, 0, 1);                    // If dst port matches, accept, else jump 1 to reject
}

// Create a simple host filter (matches src or dst IP)
int bpf_create_host_filter_ex(const char *host, bpf_program_t *program, datalink_type_t datalink) {
    struct in_addr addr;
    if (resolve_hostname(host, &addr) < 0) {
        return -1;
    }

    const uint32_t host_ip = ntohl(addr.s_addr);

    const bpf_offsets_t offsets = get_bpf_offsets(datalink);

    bpf_instruction_builder_t builder;
    bpf_builder_init(&builder);

    if (datalink == DATALINK_ETHERNET) {
        // For Ethernet, check EtherType first
        build_ethernet_header_check(&builder, offsets, ETHERTYPE_IP, 8);
        // Double-check IP version is 4
        build_ipv4_version_check(&builder, offsets, 5);
        build_ip_address_match(&builder, offsets, host_ip);
    } else {
        // For raw IP, check IPv4 version first
        build_ipv4_version_check(&builder, offsets, 5);
        build_ip_address_match(&builder, offsets, host_ip);
    }

    // Add accept/reject instructions
    bpf_builder_add_return(&builder, 0xffff);  // Accept
    bpf_builder_add_return(&builder, 0);       // Reject

    return bpf_builder_finalize(&builder, program);
}

// Create a port filter (matches src or dst port for SCTP/TCP/UDP)
int bpf_create_port_filter_ex(uint16_t port, bpf_program_t *program, datalink_type_t datalink) {
    const bpf_offsets_t offsets = get_bpf_offsets(datalink);
    bpf_instruction_builder_t builder;

    bpf_builder_init(&builder);

    if (datalink == DATALINK_ETHERNET) {
        // For Ethernet, check EtherType first
        build_ethernet_header_check(&builder, offsets, ETHERTYPE_IP, 10);
        build_port_match_with_protocols(&builder, offsets, port, 10);
    } else {
        // For raw IP, check IPv4 version first
        build_ipv4_version_check(&builder, offsets, 9);
        // Simplified version for raw IP - assumes 20-byte IP header
        bpf_builder_add_load_abs(&builder, 1, offsets.ip_proto_offset);       // Load IP protocol
        bpf_builder_add_jump_eq(&builder, IPPROTO_TCP, 2, 0);                 // If TCP, jump 2 to port check
        bpf_builder_add_jump_eq(&builder, IPPROTO_UDP, 1, 0);                 // If UDP, jump 1 to port check
        bpf_builder_add_jump_eq(&builder, IPPROTO_SCTP, 0, 4);                // If not SCTP, jump 4 to reject
        build_port_match_simple(&builder, port, 20, 22);                      // Assume 20-byte IP header
    }

    // Add accept/reject instructions
    bpf_builder_add_return(&builder, 0xffff);  // Accept
    bpf_builder_add_return(&builder, 0);       // Reject

    return bpf_builder_finalize(&builder, program);
}

// Create a protocol filter (ARP, IP, TCP, UDP, ICMP, DNS, or numeric)
int bpf_create_protocol_filter_ex(const char *proto_name, bpf_program_t *program, datalink_type_t datalink) {
    // Check for DNS special case (port-based filter)
    if (strcasecmp(proto_name, "dns") == 0) {
        return bpf_create_port_filter_ex(53, program, datalink);
    }

    const bpf_offsets_t offsets = get_bpf_offsets(datalink);
    bpf_instruction_builder_t builder;

    // Look up protocol in table
    const protocol_info_t *proto_info = find_protocol_info(proto_name);
    if (proto_info) {
        // Handle special protocols
        if (strcasecmp(proto_name, "arp") == 0) {
            if (datalink != DATALINK_ETHERNET) {
                return -1; // ARP requires Ethernet header
            }
            bpf_builder_init(&builder);
            build_ethernet_header_check(&builder, offsets, ETHERTYPE_ARP, 1);
            bpf_builder_add_return(&builder, 0xffff);  // Accept
            bpf_builder_add_return(&builder, 0);       // Reject
            return bpf_builder_finalize(&builder, program);
        }

        if (strcasecmp(proto_name, "ip") == 0) {
            bpf_builder_init(&builder);
            if (datalink == DATALINK_ETHERNET) {
                build_ethernet_header_check(&builder, offsets, ETHERTYPE_IP, 1);
            } else {
                build_ipv4_version_check(&builder, offsets, 1);
            }
            bpf_builder_add_return(&builder, 0xffff);  // Accept
            bpf_builder_add_return(&builder, 0);       // Reject
            return bpf_builder_finalize(&builder, program);
        }

        // Handle IP layer protocols (TCP, UDP, ICMP, SCTP)
        bpf_builder_init(&builder);
        if (datalink == DATALINK_ETHERNET) {
            build_ethernet_header_check(&builder, offsets, ETHERTYPE_IP, 3);
            build_protocol_check(&builder, offsets, proto_info->ip_protocol, 1);
        } else {
            build_ipv4_version_check(&builder, offsets, 3);
            build_protocol_check(&builder, offsets, proto_info->ip_protocol, 1);
        }
        bpf_builder_add_return(&builder, 0xffff);  // Accept
        bpf_builder_add_return(&builder, 0);       // Reject
        return bpf_builder_finalize(&builder, program);
    }

    // Try to parse as numeric protocol
    char *endptr;
    long val = strtol(proto_name, &endptr, 10);
    if (*endptr != '\0' || val < 0 || val > 255) {
        return -1; // Invalid protocol
    }

    const uint8_t proto_num = (uint8_t)val;
    bpf_builder_init(&builder);

    if (datalink == DATALINK_ETHERNET) {
        build_ethernet_header_check(&builder, offsets, ETHERTYPE_IP, 3);
        build_protocol_check(&builder, offsets, proto_num, 1);
    } else {
        build_ipv4_version_check(&builder, offsets, 3);
        build_protocol_check(&builder, offsets, proto_num, 1);
    }

    bpf_builder_add_return(&builder, 0xffff);  // Accept
    bpf_builder_add_return(&builder, 0);       // Reject
    return bpf_builder_finalize(&builder, program);
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
