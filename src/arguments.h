#pragma once

#include <stdbool.h>
#include <stdint.h>
#include "bpf/bpf_types.h"

typedef struct cli_args {
	int argc;
	char **argv;
	const char *exename;
	int loglevel;
	bool background;
	char *display_filters; // Comma-separated list of protocol display filters
	bpf_mode_t bpf_mode;
	char *bpf_filter_expr; // BPF filter expression
	char *interface_name;
	char *chrootdir;
	char *username;
} cli_args_t;

int parse_arguments(cli_args_t *args, int argc, char **argv);
