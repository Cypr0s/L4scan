#ifndef IP_SCAN_STRUCT_H
#define IP_SCAN_STRUCT_H

#include <stdio.h>      // fprintf
#include "error.h"      // ExitEnum
#include "parse.h"      // scanner struct
#include <netdb.h>      // addrinfo struct
#include <pcap.h>
#include <pthread.h>

#define CREATE_ENTRY(entries, pos, proto, port_num) do {    \
    entries[(pos)].target_port = (port_num);                       \
    entries[(pos)].protocol = (proto);                      \
    entries[(pos)].state = WAITING;                         \
    entries[(pos)].sent_time = (struct timespec) {0};       \
} while(0)


typedef enum {
    WAITING,
    SENT_ONCE,
    SENT_TWICE,
    OPEN,
    FILTERED,
    CLOSED
} PortStateEnum;

typedef enum {
    TCP,
    UDP
} PortTypeEnum;

typedef struct {
    unsigned short target_port;
    unsigned short source_port; // maybe??
    PortStateEnum state;
    PortTypeEnum protocol;
    struct timespec sent_time;
} ScanEntry, *ScanEntryPtr;

typedef struct {
    ScanEntryPtr entries;
    int completed_entries;
    int entries_count;

    int address_family;

    char source_ip[INET6_ADDRSTRLEN];
    char target_ip[INET6_ADDRSTRLEN];

    int tcp_socket;
    int udp_socket;
    int timeout_time;
    pthread_mutex_t mutex;
    pcap_t* sniffer;
} IPScan, *IPScanPtr;

ExitEnum ip_scan_ctor(IPScanPtr scan, ScannerPtr scanner);

void ip_scan_dtor(IPScanPtr ipscan);

void create_scan_entries(ScannerPtr scanner, ScanEntryPtr entries);

#endif