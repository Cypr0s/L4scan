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


// too much spaghetti, refactoring needed
ExitEnum scan_ipaddresses(ScannerPtr scanner, struct addrinfo* addresses, SocketsPtr socks) {
    IPScan ipscan = {0};
    ExitEnum err = ip_scan_ctor(&ipscan, scanner);
    if(err) {
        return err;
    }
 
    for(struct addrinfo* addr_ptr = addresses; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {

        set_ip_scanner(&ipscan, addr_ptr, socks, scanner);
    
        // create 2 threads
        pthread_t send, receive;
        pthread_create(&send, NULL, send_messages, (void*) &ipscan);
        pthread_create(&receive, NULL, receive_messages, (void*) &ipscan);
        pthread_join(send, NULL);
        pthread_join(receive, NULL);

        print_entry_states(&ipscan);
    }

    ip_scan_dtor(&ipscan);
    return ERR_SUCCESS;
}

// needs refactoring
void* send_messages(void* arg) {
    IPScanPtr scan = (IPScanPtr) arg;
    char message[32] = "Im a suspicious message";
    while(scan->entries_count != scan->completed_entries) {
        for(int i = 0; i < scan->entries_count; i++) {
            if(scan->entries[i].protocol == TCP) {

            }
            else if(scan->entries[i].protocol == UDP) {
                sendto(scan->udp_socket, message, sizeof(message), 0, scan->address->ai_addr, scan->address->ai_addrlen);
            }
            clock_gettime(CLOCK_MONOTONIC, &scan->entries[i].sent_time);
            scan->entries[i].state = SENT_ONCE;
        }
        check_entries();
    }
    pcap_breakloop(scan->sniffer);
    return NULL;
}

// needs refactoring
void* receive_messages(void* arg) {
    IPScanPtr scan = (IPScanPtr) arg;
    pcap_loop(scan->sniffer, -1, handle_packet, (unsigned char*) scan);
    return NULL;
}

void* handle_packet(unsigned char* arg, const struct pcap_pkthdr* header, const unsigned char* packet) {
    IPScanPtr scan = (IPScanPtr) arg;

    pthread_mutex_lock(&scan->mutex);

    pthread_mutex_unlock(&scan->mutex);
    return NULL;
}

send_blah(void) {
    for(scan->entries_count; i++) {
        PortTypeEnum protocol = scan->entries[i].protocol;
        switch(scan->entries[i].state) {
            case OPEN: case CLOSED: case FILTERED:
                continue;

            case WAITING:
                if(protocol == TCP) {
                    create_packet();
                    sendto(scan->udp_socket, message, sizeof(message), 0, scan->address->ai_addr, scan->address->ai_addrlen);
                }
                else if(protocol == UDP) {
                    sendto(scan->udp_socket, message, sizeof(message), 0, scan->address->ai_addr, scan->address->ai_addrlen);
                }
                clock_gettime(CLOCK_MONOTONIC, &scan->entries[i].sent_time);

                lock(&scan->mutex);
                scan->entries[i].state = SENT_ONCE;
                unlock(&scan->mutex);
                break;
            case SENT_ONCE:
                // if timeout time hass passes, resed tcp packet, open udp
                if(protocol == TCP) {
                    create_packet();
                    sendto(scan->udp_socket, message, sizeof(message), 0, scan->address->ai_addr, scan->address->ai_addrlen);
                }
 
                break;
            case SENT_TWICE:
                // tcp filtered
            break;
        
        }
    }
}