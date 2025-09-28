#ifndef _GNU_SOURCE
#   define _GNU_SOURCE
#endif
#include "bpf_filter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include <ctype.h>
#include <net/ethernet.h> // For ETHERTYPE_IP

// Additional BPF macros
#define BPF_OP(code)      ((code) & 0xf0) // Operation
#define BPF_SRC(code)     ((code) & 0x08) // Source of operand
#define BPF_MISCOP(code)  ((code) & 0xf8) // Miscellaneous operations
#define BPF_TAX           0x00            // Transfer A to X
#define BPF_TXA           0x80            // Transfer X to A

// BPF virtual machine state
typedef struct {
    uint32_t A;               // Accumulator
    uint32_t X;               // Index register
    uint32_t M[BPF_MEMWORDS]; // Memory store (16 slots)
} bpf_vm_state_t;

// Helper function to safely read from packet
static uint32_t safe_load_word(const uint8_t *packet, uint32_t packet_len, uint32_t offset) {
    if (offset + 4 > packet_len) return 0;
    return ntohl(*(uint32_t *)(packet + offset));
}

static uint16_t safe_load_half(const uint8_t *packet, uint32_t packet_len, uint32_t offset) {
    if (offset + 2 > packet_len) return 0;
    return ntohs(*(uint16_t *)(packet + offset));
}

static uint8_t safe_load_byte(const uint8_t *packet, uint32_t packet_len, uint32_t offset) {
    if (offset + 1 > packet_len) return 0;
    return *(uint8_t *)(packet + offset);
}

// BPF virtual machine execution
int bpf_execute_filter(const bpf_program_t *program, const uint8_t *packet, uint32_t packet_len) {
    if (!program || !program->bf_insns || program->bf_len == 0) {
        return 1; // Accept all packets if no program
    }

    bpf_vm_state_t vm = {0};
    uint32_t pc = 0; // Program counter

    while (pc < program->bf_len) {
        struct bpf_insn *insn = &program->bf_insns[pc];
        uint16_t code = insn->code;

        switch (BPF_CLASS(code)) {
            case BPF_LD:
                switch (BPF_MODE(code)) {
                    case BPF_ABS:
                        switch (BPF_SIZE(code)) {
                            case BPF_W:
                                vm.A = safe_load_word(packet, packet_len, insn->k);
                                break;
                            case BPF_H:
                                vm.A = safe_load_half(packet, packet_len, insn->k);
                                break;
                            case BPF_B:
                                vm.A = safe_load_byte(packet, packet_len, insn->k);
                                break;
                        }
                        break;
                    case BPF_IND:
                        switch (BPF_SIZE(code)) {
                            case BPF_W:
                                vm.A = safe_load_word(packet, packet_len, vm.X + insn->k);
                                break;
                            case BPF_H:
                                vm.A = safe_load_half(packet, packet_len, vm.X + insn->k);
                                break;
                            case BPF_B:
                                vm.A = safe_load_byte(packet, packet_len, vm.X + insn->k);
                                break;
                        }
                        break;
                    case BPF_IMM:
                        vm.A = insn->k;
                        break;
                    case BPF_LEN:
                        vm.A = packet_len;
                        break;
                    case BPF_MEM:
                        if (insn->k < BPF_MEMWORDS) {
                            vm.A = vm.M[insn->k];
                        }
                        break;
                }
                break;

            case BPF_LDX:
                switch (BPF_MODE(code)) {
                    case BPF_IMM:
                        vm.X = insn->k;
                        break;
                    case BPF_LEN:
                        vm.X = packet_len;
                        break;
                    case BPF_MEM:
                        if (insn->k < BPF_MEMWORDS) {
                            vm.X = vm.M[insn->k];
                        }
                        break;
                    case BPF_MSH:
                        vm.X = (safe_load_byte(packet, packet_len, insn->k) & 0xf) << 2;
                        break;
                }
                break;

            case BPF_ST:
                if (insn->k < BPF_MEMWORDS) {
                    vm.M[insn->k] = vm.A;
                }
                break;

            case BPF_STX:
                if (insn->k < BPF_MEMWORDS) {
                    vm.M[insn->k] = vm.X;
                }
                break;

            case BPF_ALU:
                switch (BPF_OP(code)) {
                    case BPF_ADD:
                        vm.A += (BPF_SRC(code) == BPF_X) ? vm.X : insn->k;
                        break;
                    case BPF_SUB:
                        vm.A -= (BPF_SRC(code) == BPF_X) ? vm.X : insn->k;
                        break;
                    case BPF_MUL:
                        vm.A *= (BPF_SRC(code) == BPF_X) ? vm.X : insn->k;
                        break;
                    case BPF_DIV:
                        {
                            uint32_t divisor = (BPF_SRC(code) == BPF_X) ? vm.X : insn->k;
                            if (divisor != 0) {
                                vm.A /= divisor;
                            } else {
                                return 0; // Division by zero, reject packet
                            }
                        }
                        break;
                    case BPF_AND:
                        vm.A &= (BPF_SRC(code) == BPF_X) ? vm.X : insn->k;
                        break;
                    case BPF_OR:
                        vm.A |= (BPF_SRC(code) == BPF_X) ? vm.X : insn->k;
                        break;
                    case BPF_LSH:
                        vm.A <<= (BPF_SRC(code) == BPF_X) ? vm.X : insn->k;
                        break;
                    case BPF_RSH:
                        vm.A >>= (BPF_SRC(code) == BPF_X) ? vm.X : insn->k;
                        break;
                    case BPF_NEG:
                        vm.A = -vm.A;
                        break;
                    case BPF_MOD:
                        {
                            uint32_t divisor = (BPF_SRC(code) == BPF_X) ? vm.X : insn->k;
                            if (divisor != 0) {
                                vm.A %= divisor;
                            } else {
                                return 0; // Division by zero, reject packet
                            }
                        }
                        break;
                    case BPF_XOR:
                        vm.A ^= (BPF_SRC(code) == BPF_X) ? vm.X : insn->k;
                        break;
                }
                break;

            case BPF_JMP:
                switch (BPF_OP(code)) {
                    case BPF_JA:
                        pc += insn->k + 1;
                        continue;
                    case BPF_JEQ:
                        {
                            uint32_t val = (BPF_SRC(code) == BPF_X) ? vm.X : insn->k;
                            if (vm.A == val) {
                                pc += insn->jt + 1; // +1 because jump is relative to next instruction
                            } else {
                                pc += insn->jf + 1; // +1 because jump is relative to next instruction
                            }
                        }
                        continue;
                    case BPF_JGT:
                        {
                            uint32_t val = (BPF_SRC(code) == BPF_X) ? vm.X : insn->k;
                            if (vm.A > val) {
                                pc += insn->jt + 1;
                            } else {
                                pc += insn->jf + 1;
                            }
                        }
                        continue;
                    case BPF_JGE:
                        {
                            uint32_t val = (BPF_SRC(code) == BPF_X) ? vm.X : insn->k;
                            if (vm.A >= val) {
                                pc += insn->jt + 1;
                            } else {
                                pc += insn->jf + 1;
                            }
                        }
                        continue;
                    case BPF_JSET:
                        {
                            uint32_t val = (BPF_SRC(code) == BPF_X) ? vm.X : insn->k;
                            if (vm.A & val) {
                                pc += insn->jt + 1;
                            } else {
                                pc += insn->jf + 1;
                            }
                        }
                        continue;
                }
                break;

            case BPF_RET:
                return (BPF_RVAL(code) == BPF_A) ? vm.A : insn->k;

            case BPF_MISC:
                switch (BPF_MISCOP(code)) {
                    case BPF_TAX:
                        vm.X = vm.A;
                        break;
                    case BPF_TXA:
                        vm.A = vm.X;
                        break;
                }
                break;
        }
        pc++;
    }

    return 0; // Default reject if we fall through
}

// Helper function to resolve hostname to IP address
static int resolve_hostname(const char *hostname, struct in_addr *addr) {
    struct hostent *host_entry;

    // Try to parse as IP address first
    if (inet_aton(hostname, addr)) {
        return 0;
    }

    // Try to resolve as hostname
    host_entry = gethostbyname(hostname);
    if (host_entry && host_entry->h_addr_list[0]) {
        memcpy(addr, host_entry->h_addr_list[0], sizeof(struct in_addr));
        return 0;
    }

    return -1;
}

// Create a simple host filter (matches src or dst IP)
int bpf_create_host_filter(const char *host, bpf_program_t *program) {
    struct in_addr addr;

    if (resolve_hostname(host, &addr) < 0) {
        return -1;
    }

    // Allocate instructions for host filter
    program->bf_len = 8;
    program->bf_insns = calloc(program->bf_len, sizeof(struct bpf_insn));
    if (!program->bf_insns) {
        return -1;
    }

    uint32_t host_ip = ntohl(addr.s_addr);

    // Load IP protocol from Ethernet frame
    program->bf_insns[0] = (struct bpf_insn){BPF_LD | BPF_H | BPF_ABS, 0, 0, 12}; // Load EtherType
    program->bf_insns[1] = (struct bpf_insn){BPF_JMP | BPF_JEQ | BPF_K, 0, 6, ETHERTYPE_IP}; // Jump if not IP

    // Check source IP
    program->bf_insns[2] = (struct bpf_insn){BPF_LD | BPF_W | BPF_ABS, 0, 0, IP_SRC_OFFSET}; // Load src IP
    program->bf_insns[3] = (struct bpf_insn){BPF_JMP | BPF_JEQ | BPF_K, 3, 0, host_ip}; // Jump if match (to instruction 7)

    // Check destination IP
    program->bf_insns[4] = (struct bpf_insn){BPF_LD | BPF_W | BPF_ABS, 0, 0, IP_DST_OFFSET}; // Load dst IP
    program->bf_insns[5] = (struct bpf_insn){BPF_JMP | BPF_JEQ | BPF_K, 1, 0, host_ip}; // Jump if match (to instruction 7)

    program->bf_insns[6] = (struct bpf_insn){BPF_RET | BPF_K, 0, 0, 0}; // Reject
    program->bf_insns[7] = (struct bpf_insn){BPF_RET | BPF_K, 0, 0, 0xffffffff}; // Accept

    return 0;
}

// Create a port filter (matches src or dst port for TCP/UDP)
int bpf_create_port_filter(uint16_t port, bpf_program_t *program) {
    // FIXME(jweyrich): This is a very naive port filter implementation which makes an assumption about the IP header size.
    // Simplified port filter - assumes standard 20-byte IP header for now
    // This makes the filter much more reliable and easier to debug
    program->bf_len = 13;
    program->bf_insns = calloc(program->bf_len, sizeof(struct bpf_insn));
    if (!program->bf_insns) {
        return -1;
    }

    // Check if packet is IP
    program->bf_insns[0] = (struct bpf_insn){BPF_LD | BPF_H | BPF_ABS, 0, 0, 12}; // Load EtherType
    program->bf_insns[1] = (struct bpf_insn){BPF_JMP | BPF_JEQ | BPF_K, 0, 11, ETHERTYPE_IP}; // Jump to reject if not IP

    // Check if protocol is TCP or UDP
    program->bf_insns[2] = (struct bpf_insn){BPF_LD | BPF_B | BPF_ABS, 0, 0, IP_PROTO_OFFSET}; // Load protocol
    program->bf_insns[3] = (struct bpf_insn){BPF_JMP | BPF_JEQ | BPF_K, 1, 0, 6}; // Jump ahead if TCP
    program->bf_insns[4] = (struct bpf_insn){BPF_JMP | BPF_JEQ | BPF_K, 0, 7, 17}; // Jump ahead if UDP, else reject

    // TCP/UDP port checks (assuming 20-byte IP header, so ports start at offset 34)
    // Check source port
    program->bf_insns[5] = (struct bpf_insn){BPF_LD | BPF_H | BPF_ABS, 0, 0, 34}; // Load src port
    program->bf_insns[6] = (struct bpf_insn){BPF_JMP | BPF_JEQ | BPF_K, 5, 0, port}; // Jump to accept if match

    // Check destination port
    program->bf_insns[7] = (struct bpf_insn){BPF_LD | BPF_H | BPF_ABS, 0, 0, 36}; // Load dst port
    program->bf_insns[8] = (struct bpf_insn){BPF_JMP | BPF_JEQ | BPF_K, 3, 0, port}; // Jump to accept if match

    // Reject paths
    program->bf_insns[9] = (struct bpf_insn){BPF_RET | BPF_K, 0, 0, 0}; // Reject (no port match)
    program->bf_insns[10] = (struct bpf_insn){BPF_RET | BPF_K, 0, 0, 0}; // Reject (not TCP/UDP)
    program->bf_insns[11] = (struct bpf_insn){BPF_RET | BPF_K, 0, 0, 0}; // Reject (not IP)

    // Accept path
    program->bf_insns[12] = (struct bpf_insn){BPF_RET | BPF_K, 0, 0, 0xffffffff}; // Accept

    return 0;
}

// Create a protocol filter (TCP, UDP, ICMP, or numeric)
int bpf_create_protocol_filter(const char *protocol, bpf_program_t *program) {
    uint8_t proto_num;

    if (strcasecmp(protocol, "tcp") == 0) {
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

    // Allocate instructions for protocol filter
    program->bf_len = 6;
    program->bf_insns = calloc(program->bf_len, sizeof(struct bpf_insn));
    if (!program->bf_insns) {
        return -1;
    }

    // Load IP protocol from Ethernet frame
    program->bf_insns[0] = (struct bpf_insn){BPF_LD | BPF_H | BPF_ABS, 0, 0, 12}; // Load EtherType
    program->bf_insns[1] = (struct bpf_insn){BPF_JMP | BPF_JEQ | BPF_K, 0, 3, ETHERTYPE_IP}; // Jump if not IP

    // Check protocol
    program->bf_insns[2] = (struct bpf_insn){BPF_LD | BPF_B | BPF_ABS, 0, 0, IP_PROTO_OFFSET}; // Load protocol
    program->bf_insns[3] = (struct bpf_insn){BPF_JMP | BPF_JEQ | BPF_K, 1, 0, proto_num}; // Jump if match

    program->bf_insns[4] = (struct bpf_insn){BPF_RET | BPF_K, 0, 0, 0}; // Reject
    program->bf_insns[5] = (struct bpf_insn){BPF_RET | BPF_K, 0, 0, 0xffffffff}; // Accept

    return 0;
}

// Free a BPF program
void bpf_free_program(bpf_program_t *program) {
    if (program && program->bf_insns) {
        free(program->bf_insns);
        program->bf_insns = NULL;
        program->bf_len = 0;
    }
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
    if (!filter_string || strlen(filter_string) == 0) {
        // Empty filter accepts all packets
        program->bf_len = 1;
        program->bf_insns = calloc(1, sizeof(struct bpf_insn));
        if (!program->bf_insns) {
            return -1;
        }
        program->bf_insns[0] = (struct bpf_insn){BPF_RET | BPF_K, 0, 0, 0xffffffff};
        return 0;
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
