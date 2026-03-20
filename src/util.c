#include "util.h"


void print_formated(char* ip_adress, unsigned short port_number, char* protocol, char* status) {
    fprintf(stdout,"%s %d %s %s", ip_adress, port_number, protocol, status);
}


ExitEnum set_filter(IPScanPtr ipscan, ScannerPtr scanner, struct addrinfo* address) {
    char ip_string[INET6_ADDRSTRLEN];
    char filter[128];

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
    }
    else {
        if(inet_ntop(AF_INET6, &((struct sockaddr_in6*)address->ai_addr)->sin6_addr, ip_string, sizeof(ip_string))) {
            perror("inet_ntop");
            return ERR_FAILURE;
        }

        if(scanner->parameter_flags & TCP_FLG && scanner->parameter_flags & UDP_FLG) {
            snprintf(filter, sizeof(filter), "src host %s and (icmp6 or tcp)", ip_string);
        }
        else if(scanner->parameter_flags & UDP_FLG && !(scanner->parameter_flags & TCP_FLG)) {
            snprintf(filter, sizeof(filter), "src host %s and icmp6", ip_string);
        }
        else {
            snprintf(filter, sizeof(filter), "src host %s and tcp", ip_string);
        }
    }

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


void set_sockets(IPScanPtr ipscan, SocketsPtr socks) {
    if(ipscan->address_family == AF_INET) {
        ipscan->tcp_socket = socks->tcp_ipv4_socket;
        ipscan->udp_socket = socks->udp_ipv4_socket;
    }
    else {
        ipscan->tcp_socket = socks->tcp_ipv6_socket;
        ipscan->udp_socket = socks->udp_ipv6_socket;
    }
}


void set_address(IPScanPtr ipscan, struct addrinfo* address, ScannerPtr scanner) {
    ipscan->address_family = address->ai_family;
    if(ipscan->address_family == AF_INET) {
        ipscan->target_ip.ipv4 = (struct sockaddr_in*) address->ai_addr;
        ipscan->source_ip.ipv4 = scanner->interface_ipv4;
    }
    else {
        ipscan->target_ip.ipv6 = (struct sockaddr_in6*) address->ai_addr;
        ipscan->source_ip.ipv6 = scanner->interface_ipv6;
    }
}


ExitEnum print_entry_states(IPScanPtr ipscan) {
    // print port states
    char target_ip[46];
    if(ipscan->address_family == AF_INET) {
        if(inet_ntop(ipscan->address_family, &(ipscan->target_ip.ipv4), target_ip, sizeof(target_ip)) == NULL) {
            perror("inet_ntop");
            return ERR_FAILURE;
        }
    }
    else {
        if(inet_ntop(ipscan->address_family, &(ipscan->target_ip.ipv6), target_ip, sizeof(target_ip)) == NULL) {
            perror("inet_ntop");
            return ERR_FAILURE;
        }
    }
    for(int i = 0; i < ipscan->entries_count; i++) {
        char* protocol = ipscan->entries[i].protocol == TCP ? "tcp" : "udp";
        switch(ipscan->entries[i].state) {
            case OPEN:
                print_formated(target_ip, ipscan->entries[i].target_port, protocol, "open\n");
                break;
            case FILTERED:
                print_formated(target_ip, ipscan->entries[i].target_port, protocol, "filtered\n");
                break;
            case CLOSED:
                print_formated(target_ip, ipscan->entries[i].target_port, protocol, "closed\n");
                break;
            default:
                break;
        }
        ipscan->entries[i].state = WAITING;
        ipscan->entries[i].sent_time.tv_nsec = 0;
    }
    return ERR_SUCCESS;
}

void create_tcp_packet() {
    
}
