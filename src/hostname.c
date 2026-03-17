/** -------------- IPK 1. project - L4 Scanner -----------------
 * @file    hostname.c
 * @author  Kristian Luptak <xluptak00>
 * @date    creation:   12.3.2026
 *          updated:    15.3.2026
 * @brief   File handles anything related to hostname argument, 
 *          eg. get_addresses_from_hostname return struct of ips that
 *          are obtained from getaddrinfo()     
 */

#include "hostname.h"

/**
 * 
 */
ExitEnum get_addresses_from_hostname(const char* input_hostname, 
                                        struct addrinfo** hostname_values, 
                                        ScannerPtr scanner) {
    struct addrinfo hints = {0};

    hints.ai_family = AF_UNSPEC;    //both ipv4 and ipv6 adresses
    hints.ai_socktype = 0;          // both UDP and TCP
    hints.ai_protocol = 0;
    hints.ai_flags = 0;             // flags

    // get addresses from input_hostname and put them into hosttname_values 
    int status = getaddrinfo(input_hostname, NULL, &hints, hostname_values);
    // addrinfo errors
    if(status != 0 || *hostname_values == NULL) {
        // invalid hostname error
        if(status == EAI_NONAME) {
            fprintf(stderr, "Invalid hostname, `%s` is not a valid hostname\n", input_hostname);
            return ERR_INVALID_ARGUMENT;
        }
        fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(status));
        return ERR_HOSTNAME;
    }

    // loop through addresses and set scanner_flags (used in socket creation)
    for(struct addrinfo* ptr = *hostname_values; ptr != NULL; ptr = ptr->ai_next) {
        if(ptr->ai_family == AF_INET) {
            scanner->parameter_flags |= IPV4_FLG;
        }
        else if(ptr->ai_family == AF_INET6) {
            scanner->parameter_flags |= IPV6_FLG;
        }
    }

    return ERR_SUCCESS;
} // get_addresses_from_hostname


//
ExitEnum scan_ipaddresses(ScannerPtr scanner, struct addrinfo* addresses, SocketsPtr socks, struct ifaddrs* interfaces) {
    IPScan scan = {0};
    scan.entries = malloc(sizeof(ScanEntry) * (scanner->tcp_count + scanner->udp_count));
    if(scan.entries == NULL) {
        fprintf(stderr, "Malloc error\n");
        return ERR_MALLOC;
    }
    create_scan_entries(scanner, scan.entries);
    scan.entries_count = scanner->tcp_count + scanner->udp_count;
    scan.timeout_time = scanner->timeout_time;
    scan.tcp_socket = -1;
    scan.udp_socket = -1;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(scanner->interface, BUFSIZ, 0, 50, errbuf);
    if(handle == NULL) {
        free(scan.entries);
        return ERR_PCAP;
    }
 
    for(struct addrinfo* addr_ptr = addresses; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
        struct ifaddrs* interface = NULL;
        for(struct ifaddrs* inter_ptr = interfaces; inter_ptr != NULL; inter_ptr = inter_ptr->ifa_next) {
            if  (inter_ptr->ifa_addr != NULL &&
                inter_ptr->ifa_name != NULL && 
                addr_ptr->ai_family == inter_ptr->ifa_addr->sa_family && 
                !strcmp(inter_ptr->ifa_name, scanner->interface)) 
            {
                interface = inter_ptr;
                break;
            }
        }
        
        // no valid interface was found
        if(interface == NULL) {
            fprintf(stderr, "No valid interface was found for address %s\n", addr_ptr->ai_canonname);
            return ERR_NO_INTERFACE;
        }
    
        // obtain IP addres as string for printing anf filter creation
        char ip_string[INET6_ADDRSTRLEN];
        char filter[128];
        if(addr_ptr->ai_family == AF_INET) {
            // create string of ipv4 address
            inet_ntop(AF_INET, &((struct sockaddr_in*)addr_ptr->ai_addr)->sin_addr, ip_string, sizeof(ip_string));
            // create filter for sniffer
            if(scanner->parameter_flags & TCP_FLG && scanner->parameter_flags & UDP_FLG) {
                snprintf(filter, sizeof(filter), "src host %s and (icmp or tcp host)", ip_string);
            }
            else if(scanner->parameter_flags & UDP_FLG && !(scanner->parameter_flags & TCP_FLG)) {
                snprintf(filter, sizeof(filter), "src host %s and icmp", ip_string);
            }
            else {
                snprintf(filter, sizeof(filter), "src host %s and tcp", ip_string);
            }
            // set sockets (if theres no flag for tcp or udp the socket will be -1 - its uninitialized)
            scan.tcp_socket = socks->tcp_ipv4_socket;
            scan.udp_socket = socks->udp_ipv4_socket;
        }
        else if (addr_ptr->ai_family == AF_INET6) {
            // create string of ipv6 address
            inet_ntop(AF_INET6, &((struct sockaddr_in6*)addr_ptr->ai_addr)->sin6_addr, ip_string, sizeof(ip_string));
            // create filter for sniffer
            if(scanner->parameter_flags & TCP_FLG && scanner->parameter_flags & UDP_FLG) {
                snprintf(filter, sizeof(filter), "src host %s and (icmp6 or tcp host)", ip_string);
            }
            else if(scanner->parameter_flags & UDP_FLG && !(scanner->parameter_flags & TCP_FLG)) {
                snprintf(filter, sizeof(filter), "src host %s and icmp6", ip_string);
            }
            else {
                snprintf(filter, sizeof(filter), "src host %s and tcp", ip_string);
            }
            // set sockets (if theres no flag for tcp or udp the socket will be -1 - its uninitialized)
            scan.tcp_socket = socks->tcp_ipv6_socket;
            scan.udp_socket = socks->udp_ipv6_socket;
        }
        else {
            fprintf(stderr, "Invalid hostname family name\n");
            return ERR_HOSTNAME;
        }
        
        scan.address = addr_ptr;


        // create 2 threads
        pthread_t send, receive;
        pthread_create(&send, NULL, send_messages, (void*) &scan);
        pthread_create(&receive, NULL, receive_messages, (void*) &scan);
        pthread_join(send, NULL);
        pthread_join(receive, NULL);

        // print port states
        for(int i = 0; i < scan.entries_count; i++) {
            char port[4] = scan.entries[i].protocol == TCP ? "tcp" : "udp";
            switch(scan.entries[i].state) {
                case OPEN:
                    print_formated(ip_string, port, port, "open\n");
                    break;
                case FILTERED:
                    print_formated(ip_string, port, port, "filtered\n");
                    break;
                case CLOSED:
                    print_formated(ip_string, port, port, "closed\n");
                    break;
                default:
                    break;
            }
            scan.entries[i].state = WAITING;
        }
    }

    free(scan.entries);
    return ERR_SUCCESS;
}


void* send_messages(void* arg) {
    IPScanPtr scan = (IPScanPtr) arg;
    for(int i = 0; i < scan->entries_count; i++) {
        if(scan->entries[i].protocol == UDP) {

        }
        else {
            
        }
    }
    return NULL;
}


void* receive_messages(void* arg) {
    return NULL;
}