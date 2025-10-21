#ifndef _DEFAULT_SOURCE
#   define _DEFAULT_SOURCE
#endif

#include "bpf/bpf_vm.h"

#include "compat/network_compat.h"
#include "log.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

//
// Reference man-page:
// name: "bpf -- Berkeley Packet Filter"
// url : https://man.freebsd.org/cgi/man.cgi?query=bpf&sektion=4&manpath=FreeBSD+4.5-RELEASE
//
// Reference paper:
// name: "The BSD Packet Filter: A New Architecture for User-level Packet Capture"
// url : http://www.tcpdump.org/papers/bpf-usenix93.pdf
//

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
                                LOG_DEBUG("rejected packet: division by zero");
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
                        // Cast to signed for negation, then back to unsigned to avoid compiler warning
                        // about applying unary minus to unsigned type.
                        // Both approaches (-vm.A and this cast) produce identical results due to C's
                        // modular arithmetic, but implementations vary: Linux kernel uses (u32)-A,
                        // libpcap uses -A directly.
                        vm.A = (uint32_t)(-(int32_t)vm.A);
                        break;
                    case BPF_MOD:
                        {
                            uint32_t divisor = (BPF_SRC(code) == BPF_X) ? vm.X : insn->k;
                            if (divisor != 0) {
                                vm.A %= divisor;
                            } else {
                                LOG_DEBUG("rejected packet: division by zero");
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
                {
                    uint32_t val = (BPF_RVAL(code) == BPF_A) ? vm.A : insn->k;
                    LOG_DEBUG("accepted packet: return value %u", val);
                    return val;
                }

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

    LOG_DEBUG("rejected packet: fall through");
    return 0; // Default reject if we fall through
}
