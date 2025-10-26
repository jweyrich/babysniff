#ifndef _DEFAULT_SOURCE
#   define _DEFAULT_SOURCE
#endif

#include "bpf/bpf_builder.h"
#include "bpf/bpf_filter.h"
#include "compat/network_compat.h"

#include <stddef.h> // for offsetof
#include <stdint.h> // for UINT8_MAX
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifndef OS_WINDOWS
#	include <netinet/ip.h>      // for struct ip
#	include <netinet/tcp.h>     // for struct tcphdr
#	include <netinet/udp.h>     // for struct udphdr
#	include <net/ethernet.h>    // for ETH_HLEN
#endif

// Helper macros for offset calculations
#define ETHER_HDR_SIZE   sizeof(struct ether_header)  // 14 bytes
#define IP_HDR_SIZE      sizeof(struct ip)            // 20 bytes (minimum)
#define TCP_HDR_SIZE     sizeof(struct tcphdr)        // 20 bytes (minimum)
#define UDP_HDR_SIZE     sizeof(struct udphdr)        // 8 bytes

// Get offsets based on datalink type
bpf_offsets_t get_bpf_offsets(datalink_type_t datalink) {
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

void bpf_builder_init(bpf_instruction_builder_t *builder) {
    builder->count = 0;
    memset(builder->instructions, 0, sizeof(builder->instructions));
}

void bpf_builder_add(bpf_instruction_builder_t *builder, struct bpf_insn insn) {
    if (builder->count == BPF_MAX_INSTR) {
        fprintf(stderr, "bpf_builder_add: Instruction limit reached\n");
        abort();
    }
    builder->instructions[builder->count].type = BPF_INSTR_NORMAL;
    builder->instructions[builder->count].insn = insn;
    builder->instructions[builder->count].goto_label = NULL;
    builder->count++;
}

void bpf_builder_add_load_abs(bpf_instruction_builder_t *builder, int size, int offset) {
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

void bpf_builder_add_jump_eq(bpf_instruction_builder_t *builder, uint32_t value, uint8_t jt, uint8_t jf) {
    bpf_builder_add(builder, (struct bpf_insn)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, value, jt, jf));
}

// Add a jump instruction that will jump to reject if condition is NOT met
void bpf_builder_add_jump_eq_to_reject(bpf_instruction_builder_t *builder, uint32_t value, uint8_t jt) {
    if (builder->count == BPF_MAX_INSTR) {
        fprintf(stderr, "bpf_builder_add_jump_eq_to_reject: Instruction limit reached\n");
        abort();
    }
    // This creates a conditional jump:
    // - If value matches: jump by jt (usually 0 = continue to next instruction)
    // - If value does NOT match: jump to reject label
    builder->instructions[builder->count].type = BPF_INSTR_GOTO;
    builder->instructions[builder->count].insn = (struct bpf_insn)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, value, jt, 0);
    builder->instructions[builder->count].goto_label = strdup("reject");
    builder->count++;
}

void bpf_builder_add_alu_and(bpf_instruction_builder_t *builder, uint32_t mask) {
    bpf_builder_add(builder, (struct bpf_insn)BPF_STMT(BPF_ALU | BPF_AND | BPF_K, mask));
}

void bpf_builder_add_return(bpf_instruction_builder_t *builder, uint32_t value) {
    bpf_builder_add(builder, (struct bpf_insn)BPF_STMT(BPF_RET | BPF_K, value));
}

// Add the reject instruction with label
void bpf_builder_add_reject(bpf_instruction_builder_t *builder) {
    bpf_builder_add_label(builder, "reject");
    bpf_builder_add_return(builder, 0);
}

// Add the accept instruction with label
void bpf_builder_add_accept(bpf_instruction_builder_t *builder) {
    bpf_builder_add_label(builder, "accept");
    bpf_builder_add_return(builder, 0xffff);
}

void bpf_builder_add_load_x_msh(bpf_instruction_builder_t *builder, int offset) {
    bpf_builder_add(builder, (struct bpf_insn)BPF_STMT(BPF_LDX | BPF_B | BPF_MSH, offset));
}

void bpf_builder_add_load_ind(bpf_instruction_builder_t *builder, int size, int offset) {
    uint16_t code = BPF_LD | BPF_IND;
    switch (size) {
        case 2: code |= BPF_H; break;  // half-word
        case 4: code |= BPF_W; break;  // word
        default: return; // Invalid size
    }
    bpf_builder_add(builder, (struct bpf_insn)BPF_STMT(code, offset));
}

// Add a label marker (doesn't generate actual instruction)
void bpf_builder_add_label(bpf_instruction_builder_t *builder, const char *label_name) {
    if (builder->count == BPF_MAX_INSTR) {
        fprintf(stderr, "bpf_builder_add_label: Instruction limit reached\n");
        abort();
    }
    builder->instructions[builder->count].type = BPF_INSTR_LABEL;
    builder->instructions[builder->count].insn = (struct bpf_insn){0}; // Unused for labels
    builder->instructions[builder->count].label_name = strdup(label_name);
    builder->count++;
}

// Add a goto instruction (conditional jump to label)
void bpf_builder_add_goto(bpf_instruction_builder_t *builder, const char *label_name, uint32_t value, uint8_t jt) {
    if (builder->count == BPF_MAX_INSTR) {
        fprintf(stderr, "bpf_builder_add_goto: Instruction limit reached\n");
        abort();
    }
    builder->instructions[builder->count].type = BPF_INSTR_GOTO;
    // Create a jump instruction template - jf will be calculated in finalize()
    builder->instructions[builder->count].insn = (struct bpf_insn)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, value, jt, 0);
    builder->instructions[builder->count].goto_label = strdup(label_name);
    builder->count++;
}

// Convenience function for jumping to reject
void bpf_builder_add_goto_reject(bpf_instruction_builder_t *builder, uint32_t value, uint8_t jt) {
    bpf_builder_add_goto(builder, "reject", value, jt);
}

// Convenience function for jumping to accept
void bpf_builder_add_goto_accept(bpf_instruction_builder_t *builder, uint32_t value, uint8_t jt) {
    bpf_builder_add_goto(builder, "accept", value, jt);
}

int bpf_builder_finalize(bpf_instruction_builder_t *builder, bpf_program_t *program) {
    // Step 1: Build label-to-index mapping
    typedef struct {
        char *name;
        int index;
    } label_map_t;

    label_map_t labels[BPF_MAX_LABELS];
    int label_count = 0;

    // Find all labels and their positions in the final instruction array
    int final_instruction_count = 0;
    for (int i = 0; i < builder->count; i++) {
        if (builder->instructions[i].type == BPF_INSTR_LABEL) {
            if (label_count >= BPF_MAX_LABELS) {
                fprintf(stderr, "bpf_builder_finalize: Too many labels (max %d)\n", BPF_MAX_LABELS);
                return -1;
            }
            labels[label_count].name = builder->instructions[i].label_name;
            labels[label_count].index = final_instruction_count;
            label_count++;
            // Labels don't generate actual instructions, so don't increment final_instruction_count
        } else {
            final_instruction_count++;
        }
    }

    // Step 2: Create final instruction array
    struct bpf_insn *final_instructions = malloc(final_instruction_count * sizeof(struct bpf_insn));
    if (!final_instructions) {
        return -1;
    }

    // Step 3: Convert wrappers to final instructions, resolving gotos
    int final_index = 0;
    for (int i = 0; i < builder->count; i++) {
        if (builder->instructions[i].type == BPF_INSTR_LABEL) {
            // Skip labels - they don't generate instructions
            continue;
        } else if (builder->instructions[i].type == BPF_INSTR_GOTO) {
            // Resolve goto to calculate jump offset
            const char *target_label = builder->instructions[i].goto_label;
            int target_index = -1;

            // Find the target label
            for (int j = 0; j < label_count; j++) {
                if (strcmp(labels[j].name, target_label) == 0) {
                    target_index = labels[j].index;
                    break;
                }
            }

            if (target_index == -1) {
                fprintf(stderr, "bpf_builder_finalize: Label '%s' not found\n", target_label);
                free(final_instructions);
                return -1;
            }

            // Calculate jump offset
            int jump_offset = target_index - final_index - 1;
            if (jump_offset < 0 || jump_offset > 255) {
                fprintf(stderr, "bpf_builder_finalize: Jump offset %d out of range for label '%s'\n",
                        jump_offset, target_label);
                free(final_instructions);
                return -1;
            }

            // Copy instruction with calculated jump offset
            final_instructions[final_index] = builder->instructions[i].insn;
            final_instructions[final_index].jf = (uint8_t)jump_offset;
        } else {
            // Normal instruction
            final_instructions[final_index] = builder->instructions[i].insn;
        }
        final_index++;
    }

    // Step 4: Pass the converted array to bpf_set_instructions
    int result = bpf_set_instructions(program, final_instructions, final_index * sizeof(struct bpf_insn));

    // Clean up
    free(final_instructions);

    // Free allocated label/goto strings
    for (int i = 0; i < builder->count; i++) {
        if (builder->instructions[i].type == BPF_INSTR_LABEL) {
            free(builder->instructions[i].label_name);
        } else if (builder->instructions[i].type == BPF_INSTR_GOTO) {
            free(builder->instructions[i].goto_label);
        }
    }

    return result;
}

// Common BPF instruction sequence builders
void build_ethernet_header_check(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint16_t ethertype) {
    bpf_builder_add_load_abs(builder, 2, offsets.ethertype_offset);  // Load EtherType
    bpf_builder_add_jump_eq_to_reject(builder, ethertype, 0);        // If not matching ethertype, jump to reject
}

void build_ipv4_version_check(bpf_instruction_builder_t *builder, bpf_offsets_t offsets) {
    bpf_builder_add_load_abs(builder, 1, offsets.ip_version_offset); // Load IP version/IHL byte
    bpf_builder_add_alu_and(builder, 0xF0);                          // Mask to get only version bits (TODO: depends on endianness?)
    bpf_builder_add_jump_eq_to_reject(builder, 0x40, 0);             // Check for IPv4, jump to reject if not (TODO: depends on endianness?)
}

void build_ipv4_address_match(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint32_t ip_addr) {
    bpf_builder_add_load_abs(builder, 4, offsets.ip_src_offset);     // Load src IP
    bpf_builder_add_jump_eq(builder, ip_addr, 2, 0);                 // If src IP matches, jump 2 to accept
    bpf_builder_add_load_abs(builder, 4, offsets.ip_dst_offset);     // Load dst IP
    bpf_builder_add_jump_eq(builder, ip_addr, 0, 1);                 // If dst IP matches, accept, else jump 1 to reject
}

void build_protocol_check(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint8_t protocol) {
    bpf_builder_add_load_abs(builder, 1, offsets.ip_proto_offset);   // Load IP protocol
    bpf_builder_add_jump_eq_to_reject(builder, protocol, 0);         // If protocol doesn't match, jump to reject
}

void build_port_match_simple(bpf_instruction_builder_t *builder, uint16_t port, int src_offset, int dst_offset) {
    bpf_builder_add_load_abs(builder, 2, src_offset);                // Load src port
    bpf_builder_add_jump_eq(builder, port, 2, 0);                    // If src port matches, jump 2 to accept
    bpf_builder_add_load_abs(builder, 2, dst_offset);                // Load dst port
    bpf_builder_add_jump_eq(builder, port, 0, 1);                    // If dst port matches, accept, else jump 1 to reject
}

void build_port_match_with_protocols(bpf_instruction_builder_t *builder, bpf_offsets_t offsets, uint16_t port) {
    // Check for TCP, UDP, or SCTP
    bpf_builder_add_load_abs(builder, 1, offsets.ip_proto_offset);   // Load IP protocol
    bpf_builder_add_jump_eq(builder, IPPROTO_TCP, 2, 0);             // If TCP, jump 2
    bpf_builder_add_jump_eq(builder, IPPROTO_UDP, 1, 0);             // If UDP, jump 1
    bpf_builder_add_jump_eq_to_reject(builder, IPPROTO_SCTP, 0);     // If not SCTP, jump to reject

    // For variable IP header length (proper implementation)
    bpf_builder_add_load_x_msh(builder, offsets.ip_header_offset);   // Load IP header length into X
    bpf_builder_add_load_ind(builder, 2, offsets.ip_header_offset);  // Load src port using X+offset
    bpf_builder_add_jump_eq(builder, port, 2, 0);                    // If src port matches, jump 2 to accept
    bpf_builder_add_load_ind(builder, 2, offsets.ip_header_offset + 2); // Load dst port using X+offset
    bpf_builder_add_jump_eq(builder, port, 0, 1);                    // If dst port matches, accept, else jump 1 to reject
}
