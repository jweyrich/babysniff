#include "log.h"
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>

static loglevel_e g_loglevel = LOGLEVEL_ERROR;

bool log_level_is_valid(int level) {
    return level >= LOGLEVEL_FATAL && level <= LOGLEVEL_TRACE;
}

void log_level_set(int level) {
    if (!log_level_is_valid(level)) {
        fprintf(stderr, "Invalid log level %d\n", level);
        return;
    }
    g_loglevel = level;
}

const char *log_level_name(loglevel_e level) {
    if (!log_level_is_valid(level)) {
        fprintf(stderr, "Invalid log level %d\n", level);
        return "UNKNOWN";
    }

    static const char *level_name[] = {
        "FATAL",
        "ERROR",
        "WARN",
        "INFO",
        "DEBUG",
        "TRACE",
    };
    return level_name[level];
}

void log_printf_narg_1(const char *format) {
    printf("%s", format);
}

void log_printf_narg_2(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void log_printf_indent_narg_3(int indent, const char *indentstr, const char *format) {
    printf("%*s%s", indent, indentstr, format);
}

void log_printf_indent_narg_4(int indent, const char *indentstr, const char *format, ...) {
    va_list args;
    va_start(args, format);
    printf("%*s", indent, indentstr);
    vprintf(format, args);
    va_end(args);
}

void log_printf_level_narg_4(const char *file, int line, loglevel_e level, const char *format) {
    if (level > g_loglevel) {
        return;
    }
    const char *level_name = log_level_name(level);
    printf("%s %s:%d %s\n", level_name, file, line, format);
}

void log_printf_level_narg_5(const char *file, int line, loglevel_e level, const char *format, ...) {
    if (level > g_loglevel) {
        return;
    }
    const char *level_name = log_level_name(level);
    va_list args;
    va_start(args, format);
    printf("%s %s:%d ", level_name, file, line);
    vprintf(format, args);
    printf("\n");
    va_end(args);
}
