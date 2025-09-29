#pragma once

#include "bpf/bpf_types.h"
#include <stdint.h>
#include <stdbool.h>
#include <netinet/in.h>

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
