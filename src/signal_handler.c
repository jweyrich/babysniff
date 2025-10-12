#include "signal_handler.h"

#include "system.h"

#include <stdio.h>
#include <signal.h>

#ifdef OS_WINDOWS
#   include <windows.h>
#endif

static volatile sig_atomic_t g_interrupted = 0;

#ifdef OS_WINDOWS

static BOOL WINAPI console_ctrl_handler(DWORD dwCtrlType) {
    switch (dwCtrlType) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
        case CTRL_SHUTDOWN_EVENT:
            printf("Received Windows console event %lu\n", dwCtrlType);
            g_interrupted = 1;
            return TRUE;
        default:
            return FALSE;
    }
}

int signal_handler_init(void) {
    if (!SetConsoleCtrlHandler(console_ctrl_handler, TRUE)) {
        return -1;
    }
    g_interrupted = 0;
    return 0;
}

void signal_handler_cleanup(void) {
    SetConsoleCtrlHandler(console_ctrl_handler, FALSE);
}

#else // POSIX

static void signal_handler(int signal) {
    printf("Received signal %d\n", signal);
    g_interrupted = 1;
}

int signal_handler_init(void) {
    struct sigaction sa;
    sa.sa_handler = signal_handler;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    // Install handlers for common termination signals
    if (sigaction(SIGINT, &sa, NULL) != 0 ||
        sigaction(SIGTERM, &sa, NULL) != 0 ||
        sigaction(SIGHUP, &sa, NULL) != 0 ||
        sigaction(SIGQUIT, &sa, NULL) != 0) {
        return -1;
    }

    g_interrupted = 0;
    return 0;
}

void signal_handler_cleanup(void) {
    struct sigaction sa;
    sa.sa_handler = SIG_DFL;
    sa.sa_flags = 0;
    sigemptyset(&sa.sa_mask);

    // Restore default handlers
    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGHUP, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
}

#endif

int signal_handler_is_interrupted(void) {
    return g_interrupted;
}
