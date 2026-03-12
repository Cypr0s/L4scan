#ifndef ERROR_H
#define ERROR_H

#include <errno.h>  // errno

typedef enum {
    EXIT_SUCCESS = 0,
    EXIT_FAILURE = 1,
    EXIT_INVALID_ARGUMENT = 2,
    EXIT_a = 3,
} ExitEnum;

#endif

