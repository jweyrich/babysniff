#include "log.h"
#include <stdio.h>
#include <stdarg.h>

void log_level_4(const char *file, int line, const char *level, const char *format) {
    printf("%s %s:%d %s\n", level, file, line, format);
}

void log_level_5(const char *file, int line, const char *level, const char *format, ...) {
    va_list args;
    va_start(args, format);
    printf("%s %s:%d ", level, file, line);
    vprintf(format, args);
    printf("\n");
    va_end(args);
}

void log_printf_1(const char *format) {
    printf("%s", format);
}

void log_printf_2(const char *format, ...) {
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
}

void log_printf_indent_3(int indent, const char *indentstr, const char *format) {
    printf("%*s%s", indent, indentstr, format);
}

void log_printf_indent_4(int indent, const char *indentstr, const char *format, ...) {
    va_list args;
    va_start(args, format);
    printf("%*s", indent, indentstr);
    vprintf(format, args);
    va_end(args);
}
