#ifndef HOSTNAME_H
#define HOSTNAME_H

#include <netdb.h>  // getaddrinfo
#include <stdlib.h> // NULL
#include <stdio.h>  // fprintf, stderr
#include "error.h"  // errno, ExitEnum
#include "parse.h"

ExitEnum get_addresses_from_hostname(const char* input_hostname, 
                                        struct addrinfo** hostname_values,
                                        ScannerPtr scanner);

#endif // HOSTNAME_H