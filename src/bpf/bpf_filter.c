#ifndef _DEFAULT_SOURCE
#   define _DEFAULT_SOURCE
#endif

#include "bpf/bpf_filter.h"

#include "bpf/bpf_builder.h"
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
#include <stdint.h> // for UINT8_MAX

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
        build_ethernet_header_check(&builder, offsets, ETHERTYPE_IP, NULL, BPF_LABEL_REJECT);
    }

    // Double-check IP version
    build_ipv4_version_check(&builder, offsets, "check_ipv4_addr", NULL);
    // build_ipv6_version_check(&builder, offsets, "check_ipv6_addr", BPF_LABEL_REJECT);

    bpf_builder_add_label(&builder, "check_ipv4_addr");
    build_ipv4_address_match(&builder, offsets, host_ip, BPF_LABEL_ACCEPT, BPF_LABEL_REJECT);

    // bpf_builder_add_label(&builder, "check_ipv6_addr");
    // build_ipv6_address_match(&builder, offsets, host_ip, BPF_LABEL_ACCEPT, BPF_LABEL_REJECT);

    bpf_builder_add_accept(&builder);
    bpf_builder_add_reject(&builder);

    return bpf_builder_finalize(&builder, program);
}

// Create a port filter (matches src or dst port for SCTP/TCP/UDP)
int bpf_create_port_filter_ex(uint16_t port, bpf_program_t *program, datalink_type_t datalink) {
    const bpf_offsets_t offsets = get_bpf_offsets(datalink);
    bpf_instruction_builder_t builder;

    bpf_builder_init(&builder);

    if (datalink == DATALINK_ETHERNET) {
        // For Ethernet, check EtherType first
        build_ethernet_header_check(&builder, offsets, ETHERTYPE_IP, NULL, BPF_LABEL_REJECT);
    }

    // For raw IP, check IPv4 version first
    build_ipv4_version_check(&builder, offsets, NULL, BPF_LABEL_REJECT);
    build_port_match_with_protocols(&builder, offsets, port);

    bpf_builder_add_accept(&builder);
    bpf_builder_add_reject(&builder);

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
            build_ethernet_header_check(&builder, offsets, ETHERTYPE_ARP, NULL, BPF_LABEL_REJECT);
            bpf_builder_add_accept(&builder);
            bpf_builder_add_reject(&builder);
            return bpf_builder_finalize(&builder, program);
        }

        if (strcasecmp(proto_name, "ip") == 0) {
            bpf_builder_init(&builder);
            if (datalink == DATALINK_ETHERNET) {
                // For Ethernet, check EtherType first
                build_ethernet_header_check(&builder, offsets, ETHERTYPE_IP, NULL, BPF_LABEL_REJECT);
            }
            build_ipv4_version_check(&builder, offsets, NULL, BPF_LABEL_REJECT);
            bpf_builder_add_accept(&builder);
            bpf_builder_add_reject(&builder);
            return bpf_builder_finalize(&builder, program);
        }

        // Handle IP layer protocols (TCP, UDP, ICMP, SCTP)
        bpf_builder_init(&builder);
        if (datalink == DATALINK_ETHERNET) {
            // For Ethernet, check EtherType first
            build_ethernet_header_check(&builder, offsets, ETHERTYPE_IP, NULL, BPF_LABEL_REJECT);
        }
        build_ipv4_version_check(&builder, offsets, NULL, BPF_LABEL_REJECT);
        build_protocol_check(&builder, offsets, proto_info->ip_protocol, BPF_LABEL_ACCEPT, BPF_LABEL_REJECT);

        bpf_builder_add_accept(&builder);
        bpf_builder_add_reject(&builder);
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
        // For Ethernet, check EtherType first
        build_ethernet_header_check(&builder, offsets, ETHERTYPE_IP, NULL, BPF_LABEL_REJECT);
    }
    build_ipv4_version_check(&builder, offsets, NULL, BPF_LABEL_REJECT);
    build_protocol_check(&builder, offsets, proto_num, BPF_LABEL_ACCEPT, BPF_LABEL_REJECT);

    bpf_builder_add_accept(&builder);
    bpf_builder_add_reject(&builder);
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
