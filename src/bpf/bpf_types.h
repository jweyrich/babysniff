
#pragma once

#include <stdint.h>

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

// Macros for filter block array initializers
#ifndef BPF_STMT
#define BPF_STMT(code, k) { (unsigned short)(code), 0, 0, k }
#endif
#ifndef BPF_JUMP
#define BPF_JUMP(code, k, jt, jf) { (unsigned short)(code), jt, jf, k }
#endif

typedef enum {
	NATIVE_BPF = 0,
	EMULATED_BPF,
} bpf_mode_t;
