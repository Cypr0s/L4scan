#ifndef UTIL_H
#define UTIL_H

#include <stdio.h> // fprintf
#include "parse.h" // scanner struct
#include "hostname.h" // ScanEntry struct
#include <netdb.h>      // addrinfo struct


#define CREATE_ENTRY(entries, pos, proto, port_num) do {    \
    entries[(pos)].port = (port_num);                       \
    entries[(pos)].protocol = (proto);                      \
    entries[(pos)].state = WAITING;                         \
    entries[(pos)].sent_time = (struct timespec) {0};       \
} while(0)


typedef struct {
    ScanEntryPtr entries;
    int completed_entries;
    int entries_count;
    char source_ip[INET6_ADDRSTRLEN];
    char target_ip[INET6_ADDRSTRLEN];

    int tcp_socket;
    int udp_socket;
    int timeout_time;
    pthread_mutex_t mutex;
    pcap_t* sniffer;
} IPScan, *IPScanPtr;

typedef struct {
    unsigned short port;
    PortStateEnum state;
    PortTypeEnum protocol;
    struct timespec sent_time;
} ScanEntry, *ScanEntryPtr;

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

void print_formated(char* ip_adress, char* port_number, char* protocol, char* status);

int create_scan_entries(ScannerPtr scanner, ScanEntryPtr entries);

ExitEnum ip_scan_ctor(IPScanPtr scan, ScannerPtr scanner);

void ip_scan_dtor(IPScanPtr ipscan);

void print_entry_states(IPScanPtr ipscan);

#endif // UTIL_H