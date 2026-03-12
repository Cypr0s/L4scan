#ifndef PARSE_H
#define PARSE_H

#include "error.h"
#include <limits.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#define HOSTNAME_FLG_POS 1
#define INTERFACE_FLG_POS 2
#define UDP_FLG_POS 3
#define TCP_FLG_POS 4
#define TIMEOUT_FLG_POS 5
#define HELP_FLG_POS 6


#define MAX_PORTS USHRT_MAX
#define LONG_BIT CHAR_BIT * sizeof(unsigned long)  // Number of bits in one long
#define NUMBER_SYSTEM 10

#define ADD_TO_ARR(arr, value) do { \
        (arr[(((unsigned long) (value)) / LONG_BIT)] |=     \
            1UL << ((unsigned long) (value)) % LONG_BIT);   \
    } while(0)

typedef struct {
    // stores all args
    char parameter_flags;
    char* interface;
    char* hostname;
    unsigned int timeout_time;
    // bitmaps (inspiration taken from IJC 1. project)
    unsigned long udp_arr[(MAX_PORTS / LONG_BIT) + 1];
    unsigned long tcp_arr[(MAX_PORTS / LONG_BIT) + 1];
} Scanner, *ScannerPtr;

ExitEnum parse_arguments(int argc, char** argv, ScannerPtr scanner);

ExitEnum convert_str_to_nums(const char* input, unsigned long* arr);

#endif