#pragma once

#include "bpf/bpf_types.h"

#include <stdint.h>

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

// Linked list node for tracking reject placeholder instructions
typedef struct reject_placeholder_node {
    uint8_t instruction_index;
    struct reject_placeholder_node *next;
} bpf_reject_placeholder_node_t;

// BPF instruction builder for cleaner filter generation
typedef struct {
    struct bpf_insn instructions[255]; // Max size for a cBPF filter
    uint8_t count;
    bpf_reject_placeholder_node_t *reject_placeholders_head; // Linked list of instructions that need reject offset fixup
    uint8_t reject_instruction_index; // Index where reject instruction will be placed
} bpf_instruction_builder_t;

// Builder initialization and finalization
void bpf_builder_init(bpf_instruction_builder_t *builder);
int bpf_builder_finalize(bpf_instruction_builder_t *builder, bpf_program_t *program);

// Basic instruction builders
void bpf_builder_add(bpf_instruction_builder_t *builder, struct bpf_insn insn);
void bpf_builder_add_load_abs(bpf_instruction_builder_t *builder, int size, int offset);
void bpf_builder_add_jump_eq(bpf_instruction_builder_t *builder, uint32_t value, uint8_t jt, uint8_t jf);
void bpf_builder_add_jump_eq_to_reject(bpf_instruction_builder_t *builder, uint32_t value, uint8_t jt);
void bpf_builder_add_alu_and(bpf_instruction_builder_t *builder, uint32_t mask);
void bpf_builder_add_return(bpf_instruction_builder_t *builder, uint32_t value);
void bpf_builder_add_reject(bpf_instruction_builder_t *builder);
void bpf_builder_add_accept(bpf_instruction_builder_t *builder);
void bpf_builder_add_load_x_msh(bpf_instruction_builder_t *builder, int offset);
void bpf_builder_add_load_ind(bpf_instruction_builder_t *builder, int size, int offset);

// Common BPF instruction sequence builders
void build_ethernet_header_check(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint16_t ethertype);
void build_ipv4_version_check(bpf_instruction_builder_t *builder, bpf_offsets_t offsets);
void build_ipv4_address_match(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint32_t ip_addr);
void build_ipv6_address_match(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint32_t ip_addr[4]);
void build_protocol_check(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint8_t protocol);
void build_port_match_simple(bpf_instruction_builder_t *builder, uint16_t port, int src_offset, int dst_offset);
void build_port_match_with_protocols(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint16_t port);

// Helper functions
bpf_offsets_t get_bpf_offsets(datalink_type_t datalink);
