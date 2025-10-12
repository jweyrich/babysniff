#include "daemon.h"

#include "system.h"

#include <stdbool.h> // bool
#include <stdio.h> // fprintf
#include <string.h> // strcmp, strchr
#include <stdlib.h> // exit

#ifdef OS_WINDOWS
#	include <windows.h>
#	include <process.h>
#else
#	include <errno.h> // errno
#	include <sys/types.h> // getpid
#	include <unistd.h> // fork
#endif

#ifdef OS_WINDOWS
/**
 * Reconstruct command line arguments excluding specified flags
 * @param args The parsed CLI arguments
 * @param skip_flags Array of flag strings to skip (must be NULL-terminated)
 * @param output Buffer to store the reconstructed command line
 * @param output_size Size of the output buffer
 * @return 0 on success, -1 on failure (buffer too small)
 */
static int reconstruct_cmdline_without_flags(const cli_args_t *args, const char **skip_flags, char *output, size_t output_size) {
	int pos = 0;

	// Add executable name (quoted in case of spaces)
	pos += snprintf(output + pos, output_size - pos, "\"%s\"", args->argv[0]);
	if (pos >= (int)output_size) {
		return -1;
	}

	// Add all arguments except specified flags
	for (int i = 1; i < args->argc; i++) {
		// Check if this argument should be skipped
		bool should_skip = false;
		for (const char **flag = skip_flags; *flag != NULL; flag++) {
			if (strcmp(args->argv[i], *flag) == 0) {
				should_skip = true;
				break;
			}
		}

		if (should_skip) {
			continue;
		}

		// Check remaining buffer space
		if (pos >= (int)output_size - 1) {
			return -1;
		}

		// Quote arguments that contain spaces
		if (strchr(args->argv[i], ' ') != NULL) {
			pos += snprintf(output + pos, output_size - pos, " \"%s\"", args->argv[i]);
		} else {
			pos += snprintf(output + pos, output_size - pos, " %s", args->argv[i]);
		}

		if (pos >= (int)output_size) {
			return -1;
		}
	}

	return 0;
}
#endif

void daemonize(const cli_args_t *args) {
#ifdef OS_WINDOWS
	// Create a detached process on Windows
	STARTUPINFO si = {0};
	PROCESS_INFORMATION pi = {0};
	si.cb = sizeof(si);
	si.dwFlags = STARTF_USESTDHANDLES;
	si.hStdInput = INVALID_HANDLE_VALUE;
	si.hStdOutput = INVALID_HANDLE_VALUE;
	si.hStdError = INVALID_HANDLE_VALUE;

	// Reconstruct command line without the background flags
	const char *background_flags[] = { "-b", "--background", NULL };
	char cmdline[4096] = {0};
	if (reconstruct_cmdline_without_flags(args, background_flags, cmdline, sizeof(cmdline)) != 0) {
		fprintf(stderr, "Failed to reconstruct command line: buffer too small\n");
		exit(EXIT_FAILURE);
	}

	// Lets recreate the process without the background flags
	if (CreateProcess(NULL, cmdline, NULL, NULL, FALSE,
	                 DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP,
	                 NULL, NULL, &si, &pi)) {
		fprintf(stderr, "%s detached with pid %lu\n", args->exename, pi.dwProcessId);
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
		exit(EXIT_SUCCESS);
	} else {
		fprintf(stderr, "Failed to create detached process: %lu\n", GetLastError());
		exit(EXIT_FAILURE);
	}
#else // POSIX
	// Create a detached process on Unix-like systems
	pid_t pid = fork();
	if (pid == 0) {
		fprintf(stderr, "%s detached with pid %u\n", args->exename, getpid());
	} else if (pid < 0) {
		fprintf(stderr, "Failed to create detached process: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	} else {
		exit(EXIT_SUCCESS);
	}
#endif
}
