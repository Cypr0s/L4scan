/** -------------- L4scan -----------------
 * @headerfile  hostname.h
 * @author      Kristian Luptak <xluptak00>
 * @date        creation:   12.3.2026
 *              updated:    15.3.2026
 * @brief       Header file contains declaration of functions used in hostname.c
 */


#ifndef HOSTNAME_H
#define HOSTNAME_H

#include <signal.h> // sig_atomic_t
#include <netdb.h>      // getaddrinfo
#include <stdlib.h>     // NULL
#include <stdio.h>      // fprintf, stderr
#include "error.h"      // errno, ExitEnum
#include "parse.h"      // Scanner struct
#include "sockets.h"    // Sockets struct
#include <pcap.h>       // pcap functions
#include "ip_scan_struct.h" // ipscan struct
#include "util.h"       // util functions
#include <net/ethernet.h>   // ethernet header check
extern volatile sig_atomic_t status;

ExitEnum get_addresses_from_hostname(struct addrinfo** hostname_values, ScannerPtr scanner);

ExitEnum scan_ip_addresses(ScannerPtr scanner, struct addrinfo* addresses, SocketsPtr socks);

ExitEnum handle_messages_fsm(IPScanPtr ipscan);

void* send_messages(void* arg);

void* receive_messages(void* arg);

void handle_packet(unsigned char* arg, const struct pcap_pkthdr* header, const unsigned char* packet);

#endif // HOSTNAME_H