#include "stdio_utils.h"

#include "system.h"

#include <stdio.h>

#ifdef OS_WINDOWS
#   include <io.h>
#   include <fcntl.h>
#else
#   include <unistd.h>
#   include <fcntl.h>
#endif

int stdio_redirect_to_null(void) {
#ifdef OS_WINDOWS
    FILE *nullfile_out, *nullfile_err, *nullfile_in;

    // Use freopen_s to redirect to NUL device
    if (freopen_s(&nullfile_in, "NUL", "r", stdin) != 0 ||
        freopen_s(&nullfile_out, "NUL", "w", stdout) != 0 ||
        freopen_s(&nullfile_err, "NUL", "w", stderr) != 0) {
        return -1;
    }

    return 0;
#else // POSIX
    int nullfd = open("/dev/null", O_RDWR);
    if (nullfd < 0) {
        return -1;
    }

    // Use dup2 to redirect to /dev/null
    if (dup2(nullfd, STDIN_FILENO) < 0 ||
        dup2(nullfd, STDOUT_FILENO) < 0 ||
        dup2(nullfd, STDERR_FILENO) < 0) {
        close(nullfd);
        return -1;
    }

    close(nullfd);
    return 0;
#endif
}

int stdio_restore_defaults(void) {
#ifdef OS_WINDOWS
    FILE *console_in, *console_out, *console_err;

    // Reopen standard streams to console
    if (freopen_s(&console_in, "CONIN$", "r", stdin) != 0 ||
        freopen_s(&console_out, "CONOUT$", "w", stdout) != 0 ||
        freopen_s(&console_err, "CONOUT$", "w", stderr) != 0) {
        return -1;
    }

    return 0;
#else // POSIX
    int ttyfd = open("/dev/tty", O_RDWR);
    if (ttyfd < 0) {
        return -1;
    }

    // Reopen standard streams to /dev/tty
    if (dup2(ttyfd, STDIN_FILENO) < 0 ||
        dup2(ttyfd, STDOUT_FILENO) < 0 ||
        dup2(ttyfd, STDERR_FILENO) < 0) {
        close(ttyfd);
        return -1;
    }

    close(ttyfd);
    return 0;
#endif
}
