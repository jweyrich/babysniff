#pragma once

#include "arguments.h"
#include <stdbool.h>

typedef struct config {
    struct {
        bool arp;
        bool dns;
        bool dns_data;
        bool eth;
        bool icmp;
        bool ip;
        bool tcp;
        bool tcp_data;
        bool udp;
        bool udp_data;
    } filters_flag;
} config_t;

int config_initialize(config_t *config, const cli_args_t *args);
