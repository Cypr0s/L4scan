#ifndef UTIL_H
#define UTIL_H

#include <stdio.h> // fprintf
#include "ip_scan_struct.h"
#include "sockets.h"
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip6.h>


struct pseudo_header_v4 {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_len;
};

struct pseudo_header_v6 {
    struct in6_addr src;
    struct in6_addr dst;
    uint32_t tcp_len;
    uint8_t zeros[3];
    uint8_t next_header;
};

void print_formated(char* ip_adress, unsigned short port_number, char* protocol, char* status);

ExitEnum print_entry_states(IPScanPtr ipscan);

ExitEnum set_filter(IPScanPtr ipscan, ScannerPtr scanner, struct addrinfo* address);

void set_sockets(IPScanPtr ipscan, SocketsPtr socks);

void set_address(IPScanPtr ipscan, struct addrinfo* address, ScannerPtr scanner);

void compute_tcp_ipv6_checksum(struct ip6_hdr* ipv6_header, struct tcphdr* tcp_header);

void create_ipv6_packet(IPScanPtr ipscan, unsigned char* buffer, unsigned short buffer_size, unsigned short dest_port);

void compute_tcp_ipv4_checksum(struct iphdr* ipv4_header, struct tcphdr* tcp_header);

void create_tcp_header(unsigned char* buffer, unsigned short dest_port);

void create_ipv4_packet(IPScanPtr ipscan, unsigned char* buffer, unsigned short buffer_size, unsigned short dest_port);

unsigned short checksum(unsigned char* addr , int count);

#endif // UTIL_H