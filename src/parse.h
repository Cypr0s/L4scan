/** -------------- IPK 1. project - L4 Scanner -----------------
 * @headerfile  parse.h
 * @author      Kristian Luptak <xluptak00>
 * @date        creation:   11.3.2026
 *              updated:    15.3.2026
 * @brief       Header file contains Scanner struct definitions, 
 *              Macros definitions which are working with Scanner sturct, 
 *              Declaration of functions used in parse.c
*/


#ifndef PARSE_H
#define PARSE_H

#include "error.h"  // ExitEnum, errno
#include <limits.h> // SHRT_MAX, CHAR_BIT
#include <stdio.h>  // prints, stdio/err
#include <string.h> // strcmp
#include <stdlib.h> // strtol, NULL
#include <netdb.h>  // in_addr, in6_addr

// flags for parameter presence used in Scanner struct (Scanner struct has one char bit flag)
#define HOSTNAME_FLG (1 << 0) 
#define INTERFACE_FLG (1 << 1) 
#define UDP_FLG (1 << 2) 
#define TCP_FLG (1 << 3) 
#define TIMEOUT_FLG (1 << 4) 
#define HELP_FLG (1 << 5) 
#define IPV4_FLG (1 << 6)
#define IPV6_FLG (1 << 7)


#define MAX_PORTS USHRT_MAX
#define LONG_BIT CHAR_BIT * sizeof(unsigned long)  // Number of bits in one long
#define NUMBER_SYSTEM 10

// macro for setting 1 bit to 1 in corresponding value spot in bitmap
#define ADD_TO_ARR(arr, value) do { \
        (arr[(((unsigned long) (value)) / LONG_BIT)] |=     \
            1UL << ((unsigned long) (value)) % LONG_BIT);   \
} while(0)

typedef enum {
    ADDR_LOOPBACK,
    ADDR_GLOBAL,
    ADDR_LINKLOCAL
}AddrFlg;

// Scanner struct which holds all important parsed data from input
typedef struct {
    char parameter_flags;
    char* interface_name;

    struct in_addr interface_ipv4;
    struct in6_addr interface_ipv6;

    char* hostname;
    unsigned int timeout_time;
    // bitmaps (inspiration taken from IJC 1. project)
    unsigned long udp_arr[(MAX_PORTS / LONG_BIT) + 1];
    unsigned short udp_count; 

    unsigned long tcp_arr[(MAX_PORTS / LONG_BIT) + 1];
    unsigned short tcp_count;
    AddrFlg address_flag;
} Scanner, *ScannerPtr;

ExitEnum parse_arguments(int argc, char** argv, ScannerPtr scanner);

ExitEnum convert_str_to_nums(const char* input, unsigned long* arr, unsigned short* count);

#endif // PARSE_H