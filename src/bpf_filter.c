#ifndef _DEFAULT_SOURCE
#   define _DEFAULT_SOURCE
#endif
#include "bpf_filter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
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

// BPF virtual machine stack size
#define BPF_VM_STACK_SIZE   16

// BPF virtual machine state
typedef struct {
    uint32_t A;                     // Accumulator
    uint32_t X;                     // Index register
    uint32_t M[BPF_VM_STACK_SIZE];  // Memory store (16 slots)
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
                        if (insn->k < BPF_VM_STACK_SIZE) {
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
                        if (insn->k < BPF_VM_STACK_SIZE) {
                            vm.X = vm.M[insn->k];
                        }
                        break;
                    case BPF_MSH:
                        vm.X = (safe_load_byte(packet, packet_len, insn->k) & 0xf) << 2;
                        break;
                }
                break;

            case BPF_ST:
                if (insn->k < BPF_VM_STACK_SIZE) {
                    vm.M[insn->k] = vm.A;
                }
                break;

            case BPF_STX:
                if (insn->k < BPF_VM_STACK_SIZE) {
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

    uint32_t host_ip = ntohl(addr.s_addr);

    const struct bpf_insn instns[] = {
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),                    // Load EtherType
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IP, 0, 6),   // If not IP, jump to reject
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, IP_SRC_OFFSET),         // Load src IP
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 3, 0, host_ip),        // If src IP matches, jump to accept
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, IP_DST_OFFSET),         // Load dst IP
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, 1, 0, host_ip),        // If dst IP matches, jump to accept
        BPF_STMT(BPF_RET | BPF_K, 0),                              // Reject
        BPF_STMT(BPF_RET | BPF_K, 0xffff),                         // Accept
    };

    // Allocate instructions
    program->bf_len = sizeof(instns) / sizeof(instns[0]);
    program->bf_insns = calloc(program->bf_len, sizeof(struct bpf_insn));
    if (!program->bf_insns) {
        return -1;
    }
    
    memcpy(program->bf_insns, instns, sizeof(instns));
    return 0;
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

    // Allocate instructions
    program->bf_len = sizeof(instns) / sizeof(instns[0]);
    program->bf_insns = calloc(program->bf_len, sizeof(struct bpf_insn));
    if (!program->bf_insns) {
        return -1;
    }

    memcpy(program->bf_insns, instns, sizeof(instns));
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

    const struct bpf_insn instns[] = {
        // Load IP protocol from Ethernet frame
        BPF_STMT(BPF_LD | BPF_H | BPF_ABS, 12),                   // Load EtherType
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, ETHERTYPE_IP, 0, 3),  // Jump if not IP

        // Check protocol
        BPF_STMT(BPF_LD | BPF_B | BPF_ABS, IP_PROTO_OFFSET),      // Load protocol
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, proto_num, 1, 0),     // Jump if match

        BPF_STMT(BPF_RET | BPF_K, 0),                             // Reject
        BPF_STMT(BPF_RET | BPF_K, 0xffff),                        // Accept
    };

    // Allocate instructions
    program->bf_len = sizeof(instns) / sizeof(instns[0]);
    program->bf_insns = calloc(program->bf_len, sizeof(struct bpf_insn));
    if (!program->bf_insns) {
        return -1;
    }

    memcpy(program->bf_insns, instns, sizeof(instns));
    return 0;
}

int bpf_create_empty_filter(bpf_program_t *program) {
    const struct bpf_insn instns[] = {
        BPF_STMT(BPF_RET | BPF_K, 0xffff), // Accept all packets
    };
    program->bf_len = sizeof(instns) / sizeof(instns[0]);
    program->bf_insns = calloc(program->bf_len, sizeof(struct bpf_insn));
    if (!program->bf_insns) {
        return -1;
    }
    memcpy(program->bf_insns, instns, sizeof(instns));
    return 0;
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
