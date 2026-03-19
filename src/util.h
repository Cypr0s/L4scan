#ifndef UTIL_H
#define UTIL_H

#include <stdio.h> // fprintf
#include "ip_scan_struct.h"
#include "sockets.h"


void print_formated(char* ip_adress, unsigned short port_number, char* protocol, char* status);

void print_entry_states(IPScanPtr ipscan);

ExitEnum set_ip_filter(IPScanPtr ipscan, ScannerPtr scanner, SocketsPtr socks, struct addrinfo* address);

#endif // UTIL_H