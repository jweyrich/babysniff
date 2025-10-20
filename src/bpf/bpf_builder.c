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
    builder->reject_placeholders_head = NULL;
    builder->reject_instruction_index = UINT8_MAX; // Invalid index initially
}

void bpf_builder_add(bpf_instruction_builder_t *builder, struct bpf_insn insn) {
    if (builder->count == 255) {
        fprintf(stderr, "bpf_builder_add: Instruction limit reached\n");
        abort();
    }
    builder->instructions[builder->count++] = insn;
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

// Add a jump instruction that will be fixed up to jump to reject instruction
void bpf_builder_add_jump_eq_to_reject(bpf_instruction_builder_t *builder, uint32_t value, uint8_t jt) {
    // Allocate new node for the linked list
    bpf_reject_placeholder_node_t *node = malloc(sizeof(bpf_reject_placeholder_node_t));
    if (node) {
        node->instruction_index = builder->count;
        node->next = builder->reject_placeholders_head;
        builder->reject_placeholders_head = node;
    }
    // Add instruction with placeholder jf offset (will be fixed up later)
    bpf_builder_add(builder, (struct bpf_insn)BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, value, jt, 255));
}

void bpf_builder_add_alu_and(bpf_instruction_builder_t *builder, uint32_t mask) {
    bpf_builder_add(builder, (struct bpf_insn)BPF_STMT(BPF_ALU | BPF_AND | BPF_K, mask));
}

void bpf_builder_add_return(bpf_instruction_builder_t *builder, uint32_t value) {
    bpf_builder_add(builder, (struct bpf_insn)BPF_STMT(BPF_RET | BPF_K, value));
}

// Add the reject instruction and mark its position for offset fixup
void bpf_builder_add_reject(bpf_instruction_builder_t *builder) {
    builder->reject_instruction_index = builder->count;
    bpf_builder_add_return(builder, 0);
}

// Add the accept instruction
void bpf_builder_add_accept(bpf_instruction_builder_t *builder) {
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

// Helper function to clean up the reject placeholders linked list
static void bpf_builder_cleanup(bpf_instruction_builder_t *builder) {
    bpf_reject_placeholder_node_t *current = builder->reject_placeholders_head;
    while (current) {
        bpf_reject_placeholder_node_t *next = current->next;
        free(current);
        current = next;
    }
    builder->reject_placeholders_head = NULL;
}

int bpf_builder_finalize(bpf_instruction_builder_t *builder, bpf_program_t *program) {
    // Fix up reject offset placeholders
    if (builder->reject_instruction_index != UINT8_MAX) {
        bpf_reject_placeholder_node_t *current = builder->reject_placeholders_head;
        while (current) {
            uint8_t insn_index = current->instruction_index;
            if (insn_index < builder->count) {
                struct bpf_insn *insn = &builder->instructions[insn_index];
                // Calculate the jump offset to the reject instruction
                uint8_t reject_offset = (uint8_t)(builder->reject_instruction_index - insn_index - 1);
                insn->jf = reject_offset;
            }
            current = current->next;
        }
    }

    int result = bpf_set_instructions(program, builder->instructions, builder->count * sizeof(struct bpf_insn));

    // Clean up the linked list
    bpf_builder_cleanup(builder);

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
