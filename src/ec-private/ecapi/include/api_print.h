#ifndef API_PRINT_H
#define API_PRINT_H

#include <stdio.h>
#include <stdbool.h>

void print_set_debug(bool on);
bool print_is_debug(void);

#define print_debug(...) if (print_is_debug()) { fprintf(stdout, __VA_ARGS__); }
#define print_err(...) fprintf(stderr, __VA_ARGS__)

#endif
