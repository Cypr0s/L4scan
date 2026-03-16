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
    scan.entries_count = scanner->tcp_count + scanner->udp_count;
    scan.tcp_socket = -1;
    scan.udp_socket = -1;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(scanner->interface, BUFSIZ, 0, 50, errbuf);
    if(handle == NULL) {
        free(scan.entries);
        return ERR_PCAP;
    }
 
    for(struct addrinfo* addr_ptr = addresses; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {
        struct ifaddrs* interface == NULL;
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
        // setup correct sniffer filter based on ip version and protocol
        char filter[128];
        if(addr_ptr->ai_family == AF_INET) {
            if(scanner->parameter_flags & TCP_FLG && scanner->parameter_flags & UDP_FLG) {
                snprintf(filter, sizeof(filter), "icmp or ??  host %s", addr_ptr->ai_canonname);    // todo
            }
            else if(scanner->parameter_flags & UDP_FLG && !(scanner->parameter_flags & TCP_FLG)) {
                snprintf(filter, sizeof(filter), "udp and dst host %s", addr_ptr->ai_canonname);
            }
            else {
                snprintf(filter, sizeof(filter), "tcp and dst host %s", addr_ptr->ai_canonname);
            }
        }
        else if(addr_ptr->ai_family == AF_INET6) {

        }
        // create 2 threads
        pthread_t send, receive;
        scan.address = addr_ptr;


    }

    free(scan.entries);
    return ERR_SUCCESS;
}