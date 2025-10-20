#pragma once

#include "bpf/bpf_builder.h"
#include "bpf/bpf_types.h"
#include "compat/network_compat.h"

#include <stdint.h>
#include <stdbool.h>

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

// Datalink type functions
void bpf_set_datalink_type(datalink_type_t datalink_type);
datalink_type_t bpf_get_datalink_type(void);

// Parser functions
bpf_filter_node_t *bpf_parse_filter_expression(const char *expression);
int bpf_compile_filter_tree(const bpf_filter_node_t *tree, bpf_program_t *program);
void bpf_free_filter_tree(bpf_filter_node_t *tree);
