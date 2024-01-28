#pragma once

#include <string.h>
#include "common.h"
#include "types.h"

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
	byte *buffer; // read buffer
	char errmsg[SNIFF_ERR_BUFSIZE];
	sniff_channel_opts_t opts;
} channel_t;

//
// Initialization
//
#define CHANNEL_INITIALIZER \
	{ -1, NULL, 0, NULL, { '\0' }, { 0 } }
#define CHANNEL_INIT(var) \
	do { \
		channel_t *ptr = (var); \
		ptr->fd = -1; \
		ptr->ifname = NULL; \
		ptr->buffer_size = 0; \
		ptr->buffer = NULL; \
		memset(ptr->errmsg, 0, sizeof(SNIFF_ERR_BUFSIZE)); \
		ptr->opts.promisc = 0; \
	} while (0)

//
// Allocation
//
channel_t *sniff_alloc_channel();
void sniff_free_channel(channel_t *channel);
