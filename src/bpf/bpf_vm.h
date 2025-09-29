#pragma once

#include "bpf/bpf_types.h"
#include <stdint.h>

// BPF opcodes (simplified subset for packet filtering)
#define BPF_CLASS(code) ((code) & 0x07)
#define BPF_SIZE(code)  ((code) & 0x18)
#define BPF_MODE(code)  ((code) & 0xe0)

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

// Additional BPF macros for VM implementation
#define BPF_OP(code)      ((code) & 0xf0) // Operation
#define BPF_SRC(code)     ((code) & 0x08) // Source of operand
#define BPF_MISCOP(code)  ((code) & 0xf8) // Miscellaneous operations
#define BPF_TAX           0x00            // Transfer A to X
#define BPF_TXA           0x80            // Transfer X to A

/**
 * Execute a BPF program against a packet
 *
 * @param program The BPF program to execute
 * @param packet The packet data to filter
 * @param packet_len The length of the packet data
 * @return Non-zero if packet should be accepted, 0 if rejected
 */
int bpf_execute_filter(const bpf_program_t *program, const uint8_t *packet, uint32_t packet_len);
