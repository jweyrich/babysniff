#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

// Include system BPF headers when available
#ifdef __linux__
    #include <linux/filter.h>
    // Linux compatibility: we'll define our own structures below
#elif defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__)
    #include <net/bpf.h>
    // BSD systems (including macOS) have bpf_insn and bpf_program natively
    #define HAVE_BPF_INSN 1
    #define HAVE_BPF_PROGRAM 1
#endif

//
// Reference man-page:
// name: "bpf -- Berkeley Packet Filter"
// url : https://man.freebsd.org/cgi/man.cgi?query=bpf&sektion=4&manpath=FreeBSD+4.5-RELEASE
//
// Reference paper:
// name: "The BSD Packet Filter: A New Architecture for User-level Packet Capture"
// url : http://www.tcpdump.org/papers/bpf-usenix93.pdf
//

// Define our unified BPF structures (used on Linux and as fallback)
#ifndef HAVE_BPF_INSN
struct bpf_insn {
    uint16_t code;    // Instruction opcode
    uint8_t  jt;      // Jump true
    uint8_t  jf;      // Jump false
    uint32_t k;       // Generic multiuse field
};
#endif

#ifndef HAVE_BPF_PROGRAM
struct bpf_program {
    unsigned int bf_len;           // Number of instructions
    struct bpf_insn *bf_insns;     // Pointer to array of instructions
};
#endif

typedef struct bpf_program bpf_program_t;

// BPF opcodes (simplified subset for packet filtering)
#define BPF_CLASS(code) ((code) & 0x07)
#define BPF_SIZE(code)  ((code) & 0x18)
#define BPF_MODE(code)  ((code) & 0xe0)

// Macros for filter block array initializers
#ifndef BPF_STMT
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#endif
#ifndef BPF_JUMP
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
#endif

// Instruction classes
#define BPF_LD    0x00  // Load
#define BPF_LDX   0x01  // Load from X
#define BPF_ST    0x02  // Store
#define BPF_STX   0x03  // Store from X
#define BPF_ALU   0x04  // Arithmetic/Logic Unit
#define BPF_JMP   0x05  // Jump
#define BPF_RET   0x06  // Return
#define BPF_MISC  0x07  // Miscellaneous

// Size modifiers
#define BPF_W     0x00  // Word (32-bit)
#define BPF_H     0x08  // Half-word (16-bit)
#define BPF_B     0x10  // Byte (8-bit)

// Mode modifiers for BPF_LD and BPF_LDX
#define BPF_IMM   0x00  // Immediate
#define BPF_ABS   0x20  // Absolute
#define BPF_IND   0x40  // Indirect
#define BPF_MEM   0x60  // Memory
#define BPF_LEN   0x80  // Length
#define BPF_MSH   0xa0  // Most Significant Half

// ALU operations
#define BPF_ADD   0x00
#define BPF_SUB   0x10
#define BPF_MUL   0x20
#define BPF_DIV   0x30
#define BPF_OR    0x40
#define BPF_AND   0x50
#define BPF_LSH   0x60  // Left shift
#define BPF_RSH   0x70  // Right shift
#define BPF_NEG   0x80
#define BPF_MOD   0x90
#define BPF_XOR   0xa0

// Jump operations
#define BPF_JA    0x00  // Jump always
#define BPF_JEQ   0x10  // Jump if equal
#define BPF_JGT   0x20  // Jump if greater than
#define BPF_JGE   0x30  // Jump if greater than or equal
#define BPF_JSET  0x40  // Jump if set

// Source operand for ALU and JMP
#define BPF_K     0x00  // Constant
#define BPF_X     0x08  // Index register

// Return values
#define BPF_RVAL(code) ((code) & 0x18)
#define BPF_A     0x10

// Common packet offsets for Ethernet frames
#define ETH_HLEN          14    // Ethernet header length
#define IP_HLEN_OFFSET    14    // IP header length offset from start of packet
#define IP_PROTO_OFFSET   23    // IP protocol offset from start of packet
#define IP_SRC_OFFSET     26    // IP source address offset
#define IP_DST_OFFSET     30    // IP destination address offset
#define TCP_SPORT_OFFSET  34    // TCP source port offset (assumes 20 byte IP header)
#define TCP_DPORT_OFFSET  36    // TCP destination port offset
#define UDP_SPORT_OFFSET  34    // UDP source port offset
#define UDP_DPORT_OFFSET  36    // UDP destination port offset

// Filter compilation and execution functions
int bpf_compile_filter(const char *filter_string, bpf_program_t *program);
int bpf_execute_filter(const bpf_program_t *program, const uint8_t *packet, uint32_t packet_len);
void bpf_free_program(bpf_program_t *program);

// Utility functions for creating common filters
int bpf_create_host_filter(const char *host, bpf_program_t *program);
int bpf_create_port_filter(uint16_t port, bpf_program_t *program);
int bpf_create_protocol_filter(const char *protocol, bpf_program_t *program);
int bpf_create_net_filter(const char *network, bpf_program_t *program);

// Helper function to allocate and copy BPF instructions
int bpf_set_instructions(bpf_program_t *program, const struct bpf_insn *instns, size_t total_size);

// High-level filter parsing (tcpdump-like syntax)
typedef enum {
    FILTER_TYPE_HOST,
    FILTER_TYPE_NET,
    FILTER_TYPE_PORT,
    FILTER_TYPE_PROTOCOL,
    FILTER_TYPE_AND,
    FILTER_TYPE_OR,
    FILTER_TYPE_NOT
} bpf_filter_type_t;

typedef struct bpf_filter_node {
    bpf_filter_type_t type;
    union {
        struct {
            struct in_addr addr;
        } host;
        struct {
            struct in_addr network;
            struct in_addr netmask;
        } net;
        struct {
            uint16_t port;
        } port;
        struct {
            uint8_t protocol;
        } protocol;
        struct {
            struct bpf_filter_node *left;
            struct bpf_filter_node *right;
        } logical;
    } data;
} bpf_filter_node_t;

// Parser functions
bpf_filter_node_t *bpf_parse_filter_expression(const char *expression);
int bpf_compile_filter_tree(const bpf_filter_node_t *tree, bpf_program_t *program);
void bpf_free_filter_tree(bpf_filter_node_t *tree);
