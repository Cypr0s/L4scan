/** -------------- IPK 1. project - L4 Scanner -----------------
 * @headerfile  hostname.h
 * @author      Kristian Luptak <xluptak00>
 * @date        creation:   12.3.2026
 *              updated:    15.3.2026
 * @brief       Header file contains declaration of functions used in hostname.c
 */


#ifndef HOSTNAME_H
#define HOSTNAME_H

#include <netdb.h>      // getaddrinfo
#include <stdlib.h>     // NULL
#include <stdio.h>      // fprintf, stderr
#include "error.h"      // errno, ExitEnum
#include "parse.h"      // Scanner struct
#include "sockets.h"    // Sockets struct
#include <stdbool.h>    // bool type
#include <pthread.h>    // threads
#include <ifaddrs.h>    // ifaddrs struct
#include <pcap.h>       // pcap functions
#include "util.h"       // ScanEntry struct, filling scan entrier

ExitEnum get_addresses_from_hostname(const char* input_hostname, 
                                        struct addrinfo** hostname_values,
                                        ScannerPtr scanner);

ExitEnum scan_ipaddresses(ScannerPtr scanner, struct addrinfo* addresses, SocketsPtr socks);

#endif // HOSTNAME_H