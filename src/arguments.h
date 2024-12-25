#pragma once

#include <stdbool.h>
#include <stdint.h>

typedef struct cli_args {
	int argc;
	char **argv;
	const char *exename;
	int loglevel;
	bool foreground;
	char *filters;
	char *interface_name;
	char *chrootdir;
	char *username;
} cli_args_t;

int parse_arguments(cli_args_t *args, int argc, char **argv);
