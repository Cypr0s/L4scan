#ifndef UTIL_H
#define UTIL_H

#include <stdio.h> // fprintf
#include "ip_scan_struct.h"
#include "sockets.h"


void print_formated(char* ip_adress, unsigned short port_number, char* protocol, char* status);

ExitEnum print_entry_states(IPScanPtr ipscan);

ExitEnum set_filter(IPScanPtr ipscan, ScannerPtr scanner, struct addrinfo* address);

void set_sockets(IPScanPtr ipscan, SocketsPtr socks);

void set_address(IPScanPtr ipscan, struct addrinfo* address, ScannerPtr scanner);

void create_tcp_packet();

#endif // UTIL_H