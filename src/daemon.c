#include "daemon.h"
#include <errno.h> // for `errno`
#include <stdio.h> // for `fprintf`
#include <stdlib.h> // for `exit`
#include <string.h> // for `strerror`
#include <sys/types.h> // for `getpid`
#include <unistd.h> // for `fork`

void daemonize(const cli_args_t *args) {
	pid_t pid = fork();
	if (pid == 0) {
		fprintf(stderr, "%s detached with pid %u\n", args->exename, getpid());
	} else if (pid < 0) {
		fprintf(stderr, "Fork failed: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	} else {
		exit(EXIT_SUCCESS);
	}
}
