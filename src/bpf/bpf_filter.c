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

// Helper function to resolve hostname to IP address
static int resolve_hostname(const char *hostname, struct in_addr *addr) {
    const int family = AF_INET; // IPv4 only because we don't yet support IPv6

    struct hostent *host_entry;
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
    program->bf_len = count;
    program->bf_insns = calloc(program->bf_len, sizeof(struct bpf_insn));
    if (!program->bf_insns) {
        return -1;
    }
    memcpy(program->bf_insns, instns, total_size);
    return 0;
}

// Create a simple host filter (matches src or dst IP)
int bpf_create_host_filter(const char *host, bpf_program_t *program) {
    struct in_addr addr;

    if (resolve_hostname(host, &addr) < 0) {
        return -1;
    }

    uint32_t host_ip = ntohl(addr.s_addr);

    const struct bpf_insn instns[] = {
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),                    // 0: Load EtherType
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IP, 0, 5),   // 1: If not IP, jump 5 to reject (7)
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, IP_SRC_OFFSET),         // 2: Load src IP
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, host_ip, 2, 0),        // 3: If src IP matches, jump 2 to accept (6)
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, IP_DST_OFFSET),         // 4: Load dst IP
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, host_ip, 0, 1),        // 5: If dst IP matches, accept (next), else jump 1 to reject (7)
        BPF_STMT(BPF_RET | BPF_K, 0xffff),                         // 6: Accept
        BPF_STMT(BPF_RET | BPF_K, 0),                              // 7: Reject
    };

    return bpf_set_instructions(program, instns, sizeof(instns));
}

// Create a port filter (matches src or dst port for SCTP/TCP/UDP)
int bpf_create_port_filter(uint16_t port, bpf_program_t *program) {
    // FIXME(jweyrich): This is a very naive port filter implementation which makes an assumption about the IP header size.
    // Simplified port filter - assumes standard 20-byte IP header for now
    const struct bpf_insn instns[] = {
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),                    // 0x28: load half-word at offset 12 (ethertype)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IPV6, 0, 8), // 0x15: if IPv6, skip next 8 instructions
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, 20),                    // 0x30: load byte at offset 20 (IPv6 next header)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_SCTP, 2, 0),   // 0x15: if SCTP, jump 2 instructions
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 1, 0),    // 0x15: if TCP, jump 1 instruction
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 17),   // 0x15: if UDP, skip next 17 instructions
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 54),                    // 0x28: load half-word at offset 54 (src port)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, port, 14, 0),          // 0x15: if port matches, jump 14 instructions
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 56),                    // 0x28: load half-word at offset 56 (dst port)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, port, 12, 13),         // 0x15: if port matches, jump 12, else jump 13
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IP, 0, 12),  // 0x15: if IPv4, skip next 12 instructions
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, IP_PROTO_OFFSET),       // 0x30: load byte at offset 23 (IPv4 protocol)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_SCTP, 2, 0),   // 0x15: if SCTP, jump 2 instructions
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_TCP, 1, 0),    // 0x15: if TCP, jump 1 instruction
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, IPPROTO_UDP, 0, 8),    // 0x15: if UDP, skip next 8 instructions
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 20),                    // 0x28: load half-word at offset 20 (IP header)
        BPF_JUMP(BPF_JMP | BPF_JSET | BPF_K, IP_OFFMASK, 6, 0),    // 0x45: if fragmented, jump 6 instructions
        BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, 14),                   // 0xb1: load IP header length
        BPF_STMT(BPF_LD | BPF_H | BPF_IND, 14),                    // 0x48: load half-word at X+14 (src port)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, port, 2, 0),           // 0x15: if port matches, jump 2 instructions
        BPF_STMT(BPF_LD | BPF_H | BPF_IND, 16),                    // 0x48: load half-word at X+16 (dst port)
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, port, 0, 1),           // 0x15: if port matches, skip next instruction
        BPF_STMT(BPF_RET | BPF_K, 0xffff),                         // 0x06: return 65535 (accept packet)
        BPF_STMT(BPF_RET | BPF_K, 0),                              // 0x06: return 0 (reject packet)
    };

    return bpf_set_instructions(program, instns, sizeof(instns));
}

// Create a protocol filter (ARP, IP, TCP, UDP, ICMP, DNS, or numeric)
int bpf_create_protocol_filter(const char *protocol, bpf_program_t *program) {
    // Check if this is an EtherType protocol (operates at layer 2)
    if (strcasecmp(protocol, "arp") == 0) {
        const struct bpf_insn instns[] = {
            BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),                    // Load EtherType
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_ARP, 0, 1),  // Jump if not ARP
            BPF_STMT(BPF_RET | BPF_K, 0xffff),                         // Accept
            BPF_STMT(BPF_RET | BPF_K, 0),                              // Reject
        };
        return bpf_set_instructions(program, instns, sizeof(instns));
    } else if (strcasecmp(protocol, "ip") == 0) {
        const struct bpf_insn instns[] = {
            BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),                   // Load EtherType
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IP, 0, 1),  // Jump if not IP
            BPF_STMT(BPF_RET | BPF_K, 0xffff),                        // Accept
            BPF_STMT(BPF_RET | BPF_K, 0),                             // Reject
        };
        return bpf_set_instructions(program, instns, sizeof(instns));
    } else if (strcasecmp(protocol, "ipv6") == 0) {
        const struct bpf_insn instns[] = {
            BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),                     // Load EtherType
            BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IPV6, 0, 1),  // Jump if not IPv6
            BPF_STMT(BPF_RET | BPF_K, 0xffff),                          // Accept
            BPF_STMT(BPF_RET | BPF_K, 0),                               // Reject
        };
        return bpf_set_instructions(program, instns, sizeof(instns));
    } else if (strcasecmp(protocol, "dns") == 0) {
		// Assume port 53
        return bpf_create_port_filter(53, program);
    }

    // Handle IP protocol types (operates at layer 3/4)
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

    // Create filter for IP protocol types (requires checking both EtherType and IP protocol field)
    const struct bpf_insn instns[] = {
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),                   // Load EtherType
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IP, 0, 3),  // Jump if not IPv4
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, IP_PROTO_OFFSET),      // Load IP protocol field
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, proto_num, 0, 1),     // Jump if protocol doesn't match
        BPF_STMT(BPF_RET | BPF_K, 0xffff),                        // Accept
        BPF_STMT(BPF_RET | BPF_K, 0),                             // Reject
    };

    return bpf_set_instructions(program, instns, sizeof(instns));
}

int bpf_create_empty_filter(bpf_program_t *program) {
    const struct bpf_insn instns[] = {
        BPF_STMT(BPF_RET | BPF_K, 0xffff), // Accept all packets
    };
    return bpf_set_instructions(program, instns, sizeof(instns));
}

// Free a BPF program
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

static void free_tokens(token_list_t *tokens) {
    for (size_t i = 0; i < tokens->count; i++) {
        free(tokens->tokens[i]);
    }
    tokens->count = 0;
}

// Simple filter expression parser (supports basic syntax like "host 192.168.1.1", "port 80", "tcp")
int bpf_compile_filter(const char *filter_string, bpf_program_t *program) {
    if (!program) {
        return -1;
    }

    if (!filter_string || strlen(filter_string) == 0) {
        return bpf_create_empty_filter(program);
    }

    token_list_t tokens;
    tokenize(filter_string, &tokens);

    if (tokens.count == 0) {
        free_tokens(&tokens);
        return -1;
    }

    int result = -1;

    // Handle simple filter expressions
    if (tokens.count == 2) {
        if (strcasecmp(tokens.tokens[0], "host") == 0) {
            result = bpf_create_host_filter(tokens.tokens[1], program);
        } else if (strcasecmp(tokens.tokens[0], "port") == 0) {
            char *endptr;
            long port = strtol(tokens.tokens[1], &endptr, 10);
            if (*endptr == '\0' && port >= 0 && port <= 65535) {
                result = bpf_create_port_filter((uint16_t)port, program);
            }
        }
    } else if (tokens.count == 1) {
        // Single protocol filter
        result = bpf_create_protocol_filter(tokens.tokens[0], program);
    }

    free_tokens(&tokens);
    return result;
}
