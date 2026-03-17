#ifndef UTIL_H
#define UTIL_H

#include <stdio.h> // fprintf
#include "parse.h" // scanner struct
#include "hostname.h" // ScanEntry struct

typedef struct {
    unsigned short port;
    PortStateEnum state;
    PortTypeEnum protocol;
} ScanEntry, *ScanEntryPtr;

typedef enum {
    WAITING,
    OPEN,
    FILTERED,
    CLOSED
} PortStateEnum;

typedef enum {
    TCP,
    UDP
} PortTypeEnum;

void print_formated(char* ip_adress, char* port_number, char* protocol, char* status);

void create_scan_entries(ScannerPtr scanner, ScanEntryPtr entries);

#endif // UTIL_H