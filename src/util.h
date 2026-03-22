/** -------------- IPK 1. project - L4 Scanner -----------------
 * @headerfile  util.h
 * @author      Kristian Luptak <xluptak00>
 * @date        creation:   15.3.2026
 *              updated:    22.3.2026
 * @brief       Header file contains declaration of functions used in util.c
 *              structs for pseaudoheaders for checksum 
 */


#ifndef UTIL_H
#define UTIL_H

#include <stdio.h> // fprintf
#include "ip_scan_struct.h" // IPScan struct
#include <netinet/ip.h> // ipv4 header checking
#include <netinet/tcp.h> // tcp header checking
#include <netinet/udp.h>    // udp header checking
#include <netinet/icmp6.h>  // icmp6 header checking
#include <netinet/ip_icmp.h>    //  icmp header checking
#include <netinet/ip6.h>    // ipv6 header checking



// ipv4 pseudoheader for cheksin
struct pseudo_header_v4 {
    uint32_t src;
    uint32_t dst;
    uint8_t zero;
    uint8_t protocol;
    uint16_t tcp_len;
};


// ipv6 pseudoheader for checksum
struct pseudo_header_v6 {
    struct in6_addr src;
    struct in6_addr dst;
    uint32_t tcp_len;
    uint8_t zeros[3];
    uint8_t next_header;
};


void print_formated(char* ip_adress, unsigned short port_number, char* protocol, char* status);

ExitEnum print_entry_states(IPScanPtr ipscan);

void compute_tcp_ipv6_checksum(struct tcphdr* tcp_header, IPScanPtr ipscan);

void compute_tcp_ipv4_checksum(struct iphdr* ipv4_header, struct tcphdr* tcp_header);

void create_tcp_header(unsigned char* buffer, unsigned short dest_port);

void create_ipv4_packet(IPScanPtr ipscan, unsigned char* buffer, 
                        unsigned short buffer_size, unsigned short dest_port);

unsigned short checksum(unsigned char* addr , int count);

ExitEnum check_timeout(ScanEntryPtr entry, long* val);

ExitEnum send_entry(unsigned char* message, unsigned short message_size, int socket, 
                ScanEntryPtr entry, struct sockaddr* address, unsigned address_size);

void handle_ipv6_header(unsigned char* char_header, IPScanPtr ipscan);

void handle_tcp_header(unsigned char* char_header, IPScanPtr ipscan);

void handle_icmpv6_header(unsigned char* char_header, IPScanPtr ipscan);

void handle_ipv4_header(unsigned char* char_header, IPScanPtr ipscan);

void handle_icmp_header(unsigned char* char_header, IPScanPtr ipscan);

#endif // UTIL_H