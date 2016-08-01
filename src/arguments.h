#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct cli_args {
	int argc;
	char **argv;
	const char *exename;
	int debuglevel;
	bool foreground;
	char *interface_name;
	char *chrootdir;
	char *username;
	uint16_t port;
} cli_args_t;

void daemonize(const cli_args_t *args);
int parse_arguments(cli_args_t *args, int argc, char **argv);
