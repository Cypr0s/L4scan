#ifndef ERROR_H
#define ERROR_H

#include <errno.h>  // errno

typedef enum {
    ERR_SUCCESS = 0,
    ERR_FAILURE = 1,
    ERR_INVALID_ARGUMENT = 2,
    ERR_GETIFADDRS = 3,
    ERR_HOSTNAME = 4,
    ERR_SOCKET = 5,
    ERR_NO_INTERFACE = 6,
    ERR_PCAP = 7,


    ERR_MALLOC= 99,
} ExitEnum;

#endif

