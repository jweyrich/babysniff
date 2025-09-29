#pragma once

#include "bpf/bpf_filter.h"
#include <stdint.h>

/**
 * Execute a BPF program against a packet
 *
 * @param program The BPF program to execute
 * @param packet The packet data to filter
 * @param packet_len The length of the packet data
 * @return Non-zero if packet should be accepted, 0 if rejected
 */
int bpf_execute_filter(const bpf_program_t *program, const uint8_t *packet, uint32_t packet_len);
