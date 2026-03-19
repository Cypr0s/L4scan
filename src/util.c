#include "util.h"


void print_formated(char* ip_adress, unsigned short port_number, char* protocol, char* status) {
    fprintf(stdout,"%s %d %s %s", ip_adress, port_number, protocol, status);
}


ExitEnum set_ip_filter(IPScanPtr ipscan, ScannerPtr scanner, SocketsPtr socks, struct addrinfo* address) {
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

        ipscan->tcp_socket = socks->tcp_ipv4_socket;
        ipscan->udp_socket = socks->udp_ipv4_socket;
        strcpy(ipscan->source_ip, scanner->interface_ipv4);
        ipscan->address_family = AF_INET;
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
        strcpy(ipscan->source_ip, scanner->interface_ipv6);
        ipscan->address_family = AF_INET6;
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
                print_formated(ipscan->target_ip, ipscan->entries[i].target_port, protocol, "open\n");
                break;
            case FILTERED:
                print_formated(ipscan->target_ip, ipscan->entries[i].target_port, protocol, "filtered\n");
                break;
            case CLOSED:
                print_formated(ipscan->target_ip, ipscan->entries[i].target_port, protocol, "closed\n");
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
