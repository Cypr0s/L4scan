#include "util.h"

void print_formated(char* ip_adress, char* port_number, char* protocol, char* status) {
    fprintf(stdout,"%s %s %s %s", ip_adress, port_number, protocol, status);
}

void create_scan_entries(ScannerPtr scanner, ScanEntryPtr entries) {
    int entry_pos = 0;
    for(unsigned short i = 0; i < MAX_PORTS; i++) {
        if(scanner->tcp_arr[i / LONG_BIT] & (1UL << (i % LONG_BIT))) {
            entries[entry_pos].port = i;
            entries[entry_pos].protocol = TCP;
            entries[entry_pos].state = WAITING;
            entry_pos++;
        }

        if(scanner->udp_arr[i / LONG_BIT] & (1UL << (i % LONG_BIT))) {
            entries[entry_pos].port = i;
            entries[entry_pos].protocol = UDP;
            entries[entry_pos].state = WAITING;
            entry_pos++;
        }
    }
}
