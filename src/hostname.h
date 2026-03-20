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
#include "ip_scan_struct.h"
#include "util.h"
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/icmp6.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>

ExitEnum get_addresses_from_hostname(struct addrinfo** hostname_values, ScannerPtr scanner);

ExitEnum scan_ipaddresses(ScannerPtr scanner, struct addrinfo* addresses, SocketsPtr socks);

ExitEnum handle_messages_fsm(IPScanPtr ipscan);

void* send_messages(void* arg);

void* receive_messages(void* arg);

void handle_packet(unsigned char* arg, const struct pcap_pkthdr* header, const unsigned char* packet);

#endif // HOSTNAME_H