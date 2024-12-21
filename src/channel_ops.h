#pragma once

#include <stdlib.h>
#include "common.h"
#include "channel.h"
#include "config.h"

//
// Types
//
struct sniff_channel_ops {
	channel_t *(*open)(const char *ifname, int promisc, size_t buffer_size);
	void (*close)(channel_t *channel);
	int (*read)(channel_t *channel, long timeout);
	int (*write)(channel_t *channel, const byte *data, size_t length);
	int (*setnonblock)(channel_t *channel, int nonblock);
};

//
// Operations
//
channel_t *sniff_open(const char *ifname, int promisc, size_t buffer_size);
void sniff_close(channel_t *channel);
int sniff_setnonblock(channel_t *channel, int nonblock);
int sniff_readloop(channel_t *channel, long timeout, const config_t *config);
int sniff_channel_set_error_msg(channel_t *channel, const char *format, ...);
const char *sniff_channel_get_error_msg(channel_t *channel);

// TODO(jweyrich): add error codes and subsequent functions
