#ifndef PARSE_H
#define PARSE_H

#include "error.h"  // ExitEnum, errno
#include <limits.h> // SHRT_MAX, CHAR_BIT
#include <stdio.h>  // prints, stdio/err
#include <string.h> // strcmp
#include <stdlib.h> // strtol, NULL


#define HOSTNAME_FLG (1 << 1) 
#define INTERFACE_FLG (1 << 2) 
#define UDP_FLG (1 << 3) 
#define TCP_FLG (1 << 4) 
#define TIMEOUT_FLG (1 << 5) 
#define HELP_FLG (1 << 6) 


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