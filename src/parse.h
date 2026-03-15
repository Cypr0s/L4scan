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

// Scanner struct which holds all important parsed data from input
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


/**
 * @def     parse_arguments
 * @brief   Parses input arguments, loads information into Scanner struct,
 *          returns ERR_INVALID_ARUMENT when invalid argument is inputted.
 * @param   argc - count ofinput arguments passed from main()
 * @param   argv - input arguments passed from main()
 * @param   scanner - pinter to Scanner struct where important parsed information is stored
 *                    (eg. interface name, hostname name, bitmap of ports)
 * @return  ERR_SUCCESS(0) if parsing was successful or help argument was provided
 *          ERR_INVALID_ARGUMENT(2) if there was either invalid Argument, invalid argument Value,
 *          Multiple uses of any argument or no Required argument was 
 *          provided(hostname, interface atleast one of TCP/UDP ports)
 */
ExitEnum parse_arguments(int argc, char** argv, ScannerPtr scanner);


/**
 * @def     convert_str_to_nums
 * @brief   converts range of ports string(eg. 80-443 or 67, 68, 69 or 65536) 
 *          into bitmap which is stored in arr parameter
 * @param   input - string which is converted to bitmap
 * @param   arr - bitmap (longs) from struct Scanner where result bits are set to 1
 * @return  ERR_INVALID_ARGUMENT(2) upon strtol errors or invalid input
 *          (eg. number is out of range for ports or invalid characters).
 *          ERR_SUCCESS(0) if no errors happened
 */
ExitEnum convert_str_to_nums(const char* input, unsigned long* arr);

#endif // PARSE_H