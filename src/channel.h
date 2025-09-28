#pragma once

#include "channel_ops_common.h"
#include "bpf_filter.h"
#include <stdint.h>
#include <string.h>

#define SNIFF_DEFAULT_BUFSIZE 4096 // TODO(jweyrich): move it to a per-strategy basis
#define SNIFF_ERR_BUFSIZE 255

//
// Types
//
typedef struct sniff_channel_opts {
	int promisc;
} sniff_channel_opts_t;

typedef struct sniff_channel {
	int fd;
	char *ifname; // interface name
	size_t buffer_size; // read buffer size
	uint8_t *buffer; // read buffer
	char errmsg[SNIFF_ERR_BUFSIZE];
	sniff_channel_opts_t opts;
	bpf_program_t bpf_filter; // BPF filter program
	bool has_bpf_filter; // Flag indicating if BPF filter is active
} channel_t;

//
// Initialization
//
#define CHANNEL_INITIALIZER \
	{ -1, NULL, 0, NULL, { '\0' }, { 0 }, { 0, NULL }, 0 }
#define CHANNEL_INIT(var) \
	do { \
		channel_t *ptr = (var); \
		ptr->fd = -1; \
		ptr->ifname = NULL; \
		ptr->buffer_size = 0; \
		ptr->buffer = NULL; \
		memset(ptr->errmsg, 0, sizeof(SNIFF_ERR_BUFSIZE)); \
		ptr->opts.promisc = 0; \
		ptr->bpf_filter.bf_len = 0; \
		ptr->bpf_filter.bf_insns = NULL; \
		ptr->has_bpf_filter = 0; \
	} while (0)

//
// Allocation
//
channel_t *sniff_alloc_channel(void);
void sniff_free_channel(channel_t *channel);
