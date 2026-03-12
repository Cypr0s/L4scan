#ifndef l4scan.h
#define l4scan.h

#include "error.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <limits.h>

#define CHAR_BIT sizeof(char)   // Number of bits in one byte
#define MAX_PORTS USHRT_MAX
#define LONG_BIT sizeof(char) * sizeof(long)

#define ADD_TO_ARR(arr, value) do { \
        (arr[(((unsigned long) (value)) / LONG_BIT)] |=     \
            1UL << ((unsigned long) (value)) % LONG_BIT);   \
    } while(0)

typedef struct {
    char* interface;
    unsigned* timeout_time;
    char* host;
    // bitmaps (inspiration taken from IJC 1. project)
    unsigned long udp_arr[MAX_PORTS / LONG_BIT];
    unsigned long tcp_arr[MAX_PORTS / LONG_BIT];
} Scanner, *ScannerPtr;


#endif