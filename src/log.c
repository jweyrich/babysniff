#include "log.h"
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>

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

void log_printf_level_narg_4(const char *file, int line, log_level_e level, const char *format) {
    log_level_e current_level = log_level_get();
    if (level > current_level) {
        return;
    }
    const char *level_name = log_level_name(level);
    printf("%s %s:%d %s\n", level_name, file, line, format);
}

void log_printf_level_narg_5(const char *file, int line, log_level_e level, const char *format, ...) {
    log_level_e current_level = log_level_get();
    if (level > current_level) {
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
