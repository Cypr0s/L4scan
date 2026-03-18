#include "util.h"


void print_formated(char* ip_adress, char* port_number, char* protocol, char* status) {
    fprintf(stdout,"%s %s %s %s", ip_adress, port_number, protocol, status);
}

int create_scan_entries(ScannerPtr scanner, ScanEntryPtr entries) {
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


ExitEnum ip_scan_ctor(IPScanPtr ipscan, ScannerPtr scanner) {
    // firstly try creating error prone things
    ipscan->entries = malloc(sizeof(ScanEntry) * (scanner->tcp_count + scanner->udp_count));
    if(ipscan->entries == NULL) {
        fprintf(stderr, "Malloc error\n");
        return ERR_MALLOC;
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    ipscan->sniffer = pcap_open_live(scanner->interface, BUFSIZ, 0, 50, errbuf);
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


ExitEnum set_ip_filter(IPScanPtr ipscan, ScannerPtr scanner, SocketsPtr socks, struct addrinfo* address) {
    char ip_string[INET6_ADDRSTRLEN];
    char filter[128];
    char* parameters;

    if(address->ai_family == AF_INET) {
        if(inet_ntop(AF_INET, &((struct sockaddr_in*)address->ai_addr)->sin_addr, ip_string, sizeof(ip_string)) == NULL){
            perror("inet_ntop");
            return ERR_FAILURE;
        }

        if(scanner->parameter_flags & TCP_FLG && scanner->parameter_flags & UDP_FLG) {
            snprintf(filter, sizeof(filter), "src host %s and (icmp or tcp)", ip_string);
        }
        else if(scanner->parameter_flags & UDP_FLG && !(scanner->parameter_flags & TCP_FLG)) {
            snprintf(filter, sizeof(filter), "src host %s and icmp", ip_string);
        }
        else {
            snprintf(filter, sizeof(filter), "src host %s and tcp", ip_string);
        }

        ipscan->tcp_socket = socks->tcp_ipv4_socket;
        ipscan->udp_socket = socks->udp_ipv4_socket;
    }
    else if (address->ai_family == AF_INET6) {

        inet_ntop(AF_INET6, &((struct sockaddr_in6*)address->ai_addr)->sin6_addr, ip_string, sizeof(ip_string));

        if(scanner->parameter_flags & TCP_FLG && scanner->parameter_flags & UDP_FLG) {
            snprintf(filter, sizeof(filter), "src host %s and (icmp6 or tcp)", ip_string);
        }
        else if(scanner->parameter_flags & UDP_FLG && !(scanner->parameter_flags & TCP_FLG)) {
            snprintf(filter, sizeof(filter), "src host %s and icmp6", ip_string);
        }
        else {
            snprintf(filter, sizeof(filter), "src host %s and tcp", ip_string);
        }
        ipscan->tcp_socket = socks->tcp_ipv6_socket;
        ipscan->udp_socket = socks->udp_ipv6_socket;
    }
    else {
        fprintf(stderr, "Invalid hostname family name\n");
        return ERR_HOSTNAME;
    }
    strcpy(ipscan->target_ip, ip_string);
    // set filter
    struct bpf_program fp;
    if(pcap_compile(ipscan->sniffer, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile error\n");
        return ERR_PCAP;
    }
    if(pcap_setfilter(ipscan->sniffer, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter error\n");
        return ERR_PCAP;
    }

    return ERR_SUCCESS;
}

void print_entry_states(IPScanPtr ipscan) {
    // print port states
    for(int i = 0; i < ipscan->entries_count; i++) {
        char* protocol = ipscan->entries[i].protocol == TCP ? "tcp" : "udp";
        switch(ipscan->entries[i].state) {
            case OPEN:
                print_formated(ipscan->target_ip, ipscan->entries[i].port, protocol, "open\n");
                break;
            case FILTERED:
                print_formated(ipscan->target_ip, ipscan->entries[i].port, protocol, "filtered\n");
                break;
            case CLOSED:
                print_formated(ipscan->target_ip, ipscan->entries[i].port, protocol, "closed\n");
                break;
            default:
                break;
        }
        ipscan->entries[i].state = WAITING;
        ipscan->entries[i].sent_time.tv_nsec = 0;
    }
}

void create_tcp_packet() {
    
}
