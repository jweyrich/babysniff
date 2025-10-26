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

// BPF instruction types for the goto label system
typedef enum {
    BPF_INSTR_NORMAL,  // Regular BPF instruction
    BPF_INSTR_GOTO,    // Goto instruction (jump to label)
    BPF_INSTR_LABEL    // Label marker (doesn't generate actual instruction)
} bpf_instruction_type_t;

#define BPF_LABEL_ACCEPT "accept"
#define BPF_LABEL_REJECT "reject"

// Wrapper for BPF instructions to support goto labels
typedef struct {
    bpf_instruction_type_t type;
    struct bpf_insn insn;
    union {
        struct {
            char *jt_label; // For GOTO instructions - jt target label name
            char *jf_label; // For GOTO instructions - jf target label name
        } goto_labels;
        char *label_name;   // For LABEL instructions - label name
    };
} bpf_instruction_wrapper_t;

#define BPF_MAX_INSTR 255   // Max number of instructions supported by cBPF
#define BPF_MAX_LABELS 32   // Max number of labels supported (we can customize it)

// BPF instruction builder for cleaner filter generation
typedef struct {
    bpf_instruction_wrapper_t instructions[BPF_MAX_INSTR];
    uint8_t count;
} bpf_instruction_builder_t;

// Builder initialization and finalization
void bpf_builder_init(bpf_instruction_builder_t *builder);
int bpf_builder_finalize(bpf_instruction_builder_t *builder, bpf_program_t *program);

// Basic instruction builders
void bpf_builder_add(bpf_instruction_builder_t *builder, struct bpf_insn insn);
void bpf_builder_add_load_abs(bpf_instruction_builder_t *builder, int size, int offset);
void bpf_builder_add_jump_eq(bpf_instruction_builder_t *builder, uint32_t value, uint8_t jt, uint8_t jf);
void bpf_builder_add_alu_and(bpf_instruction_builder_t *builder, uint32_t mask);
void bpf_builder_add_return(bpf_instruction_builder_t *builder, uint32_t value);
void bpf_builder_add_reject(bpf_instruction_builder_t *builder);
void bpf_builder_add_accept(bpf_instruction_builder_t *builder);
void bpf_builder_add_load_x_msh(bpf_instruction_builder_t *builder, int offset);
void bpf_builder_add_load_ind(bpf_instruction_builder_t *builder, int size, int offset);

// Goto label system functions
void bpf_builder_add_label(bpf_instruction_builder_t *builder, const char *label_name);
void bpf_builder_add_label_jump_eq(bpf_instruction_builder_t *builder, uint32_t value, const char *jt_label_name, const char *jf_label_name);

// Common BPF instruction sequence builders
void build_ethernet_header_check(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint16_t ethertype, const char *jt_label_name, const char *jf_label_name);
void build_ipv4_version_check(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, const char *jt_label_name, const char *jf_label_name);
void build_ipv6_version_check(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, const char *jt_label_name, const char *jf_label_name);
void build_ipv4_address_match(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint32_t ip_addr, const char *jt_label_name, const char *jf_label_name);
void build_ipv6_address_match(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint32_t ip_addr[4], const char *jt_label_name, const char *jf_label_name);
void build_protocol_check(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint8_t protocol, const char *jt_label_name, const char *jf_label_name);
void build_port_match_simple(bpf_instruction_builder_t *builder, uint16_t port, int src_offset, int dst_offset, const char *jt_label_name, const char *jf_label_name);
void build_port_match_with_protocols(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint16_t port);

// Helper functions
bpf_offsets_t get_bpf_offsets(datalink_type_t datalink);
