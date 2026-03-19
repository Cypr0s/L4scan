#include "ip_scan_struct.h"

ExitEnum ip_scan_ctor(IPScanPtr ipscan, ScannerPtr scanner) {
    // firstly try creating error prone things
    ipscan->entries = malloc(sizeof(ScanEntry) * (scanner->tcp_count + scanner->udp_count));
    if(ipscan->entries == NULL) {
        fprintf(stderr, "Malloc error\n");
        return ERR_MALLOC;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    ipscan->sniffer = pcap_open_live(scanner->interface_name, BUFSIZ, 0, 50, errbuf);
    if(ipscan->sniffer == NULL) {
        free(ipscan->entries);
        fprintf(stderr, "pcap_open_live error: %s\n", errbuf);
        return ERR_PCAP;
    }

    if(pthread_mutex_init(&(ipscan->mutex), NULL) != 0) {
        free(ipscan->entries);
        pcap_close(ipscan->sniffer);
        fprintf(stderr, "Mutex init error\n");
        return ERR_MUTEX;
    }

    // set parameters
    create_scan_entries(scanner, ipscan->entries);
    ipscan->entries_count = scanner->tcp_count + scanner->udp_count;
    ipscan->timeout_time = scanner->timeout_time;
    ipscan->tcp_socket = -1;
    ipscan->udp_socket = -1;
    return ERR_SUCCESS;
}

void ip_scan_dtor(IPScanPtr ipscan) {
    if(ipscan->entries != NULL) {
        free(ipscan->entries);
    }
    if(ipscan->sniffer != NULL) {
        pcap_close(ipscan->sniffer);
    }
    pthread_mutex_destroy(&(ipscan->mutex));
}

void create_scan_entries(ScannerPtr scanner, ScanEntryPtr entries) {
    int entry_pos = 0;
    for(unsigned short i = 0; i < MAX_PORTS; i++) {
        if(scanner->tcp_arr[i / LONG_BIT] & (1UL << (i % LONG_BIT))) {
            CREATE_ENTRY(entries, entry_pos, TCP, i);
            entry_pos++;
        }

        if(scanner->udp_arr[i / LONG_BIT] & (1UL << (i % LONG_BIT))) {
            CREATE_ENTRY(entries, entry_pos, UDP, i);
            entry_pos++;
        }
    }
}