// #include <stdarg.h>

#include "api_print.h"

static bool debug_on = false;

void print_set_debug(bool on) {
    debug_on = on;
}

bool print_is_debug(void) {
    return debug_on;
}
/*
void print_debug(char *fmt, ...) {
    if (print_is_debug()) {
        va_list args; va_start(args, fmt);
        vfprintf(stdout, fmt, args);
        va_end(args);
    }
}

void print_err(char *fmt, ...) {
    va_list args; va_start(args, fmt);
    vfprintf(stderr, fmt, args);
    va_end(args);
}*/