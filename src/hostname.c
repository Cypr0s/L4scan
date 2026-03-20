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
ExitEnum get_addresses_from_hostname(struct addrinfo** hostname_values, ScannerPtr scanner) {
    struct addrinfo hints = {0};

    hints.ai_family = AF_UNSPEC;    //both ipv4 and ipv6 adresses
    hints.ai_socktype = 0;          // both UDP and TCP
    hints.ai_protocol = 0;
    hints.ai_flags = 0;             // flags

    // get all addresses from "hostname"
    int status = getaddrinfo(scanner->hostname, NULL, &hints, hostname_values);
    // addrinfo errors
    if(status != 0 || *hostname_values == NULL) {
        // invalid hostname error
        if(status == EAI_NONAME) {
            fprintf(stderr, "Invalid hostname, `%s` is not a valid hostname\n", scanner->hostname);
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

        set_filter(&ipscan, scanner, addr_ptr);
        set_address(&ipscan, addr_ptr, scanner);
        set_sockets(&ipscan, socks);
    
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
    IPScanPtr ipscan = (IPScanPtr) arg;

    while(1) {
        pthread_mutex_lock(&(ipscan->mutex));
        if(ipscan->entries_count == ipscan->completed_entries) {
            pthread_mutex_unlock(&(ipscan->mutex));
            break;
        }
        pthread_mutex_unlock(&(ipscan->mutex));
    
        if(handle_messages_fsm(ipscan)) {
            break;
        }
    }
    pcap_breakloop(ipscan->sniffer);
    return NULL;
}


// modularization needed, kinda finished???
ExitEnum handle_messages_fsm(IPScanPtr ipscan) {
    int address_size = ipscan->address_family == AF_INET6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    char message[32] = "Im a suspicious message";
    for(int i = 0; i < ipscan->entries_count; i++) {
        if(ipscan->entries[i].state == OPEN || ipscan->entries[i].state == CLOSED || ipscan->entries[i].state == FILTERED) {
            continue;
        }
        switch(ipscan->entries[i].state) {
            case OPEN: case CLOSED: case FILTERED:
                continue;
            case WAITING:
                pthread_mutex_lock(&(ipscan->mutex));
                if(ipscan->entries[i].protocol == TCP) {
                    create_tcp_packet();
                    if(ipscan->address_family == AF_INET6) {
                        ipscan->target_ip.ipv6->sin6_port = htons(ipscan->entries[i].target_port);
                        if(sendto(ipscan->tcp_socket, &message, strlen(message), 0, (struct sockaddr*) ipscan->target_ip.ipv6, address_size)) {
                            perror("sendto");
                            pthread_mutex_unlock(&(ipscan->mutex));
                            return ERR_FAILURE;
                        }
                    }
                    else {
                        ipscan->target_ip.ipv4->sin_port = htons(ipscan->entries[i].target_port);
                        if(sendto(ipscan->tcp_socket, &message, strlen(message), 0,(struct sockaddr*) ipscan->target_ip.ipv4, address_size)) {
                            perror("sendto");
                            pthread_mutex_unlock(&(ipscan->mutex));
                            return ERR_FAILURE;
                        }
                    }
                }
                else if(ipscan->entries[i].protocol == UDP) {
                    if(ipscan->address_family == AF_INET6) {
                        ipscan->target_ip.ipv6->sin6_port = htons(ipscan->entries[i].target_port);
                        if(sendto(ipscan->udp_socket, &message, strlen(message), 0, (struct sockaddr*) ipscan->target_ip.ipv6, address_size) == 0) {
                            perror("sendto");
                            pthread_mutex_unlock(&(ipscan->mutex));
                            return ERR_FAILURE;
                        }
                    }
                    else {
                        ipscan->target_ip.ipv4->sin_port = htons(ipscan->entries[i].target_port);
                        if(sendto(ipscan->udp_socket, &message, strlen(message), 0, (struct sockaddr*) ipscan->target_ip.ipv6, address_size) == 0) {
                            perror("sendto");
                            pthread_mutex_unlock(&(ipscan->mutex));
                            return ERR_FAILURE;
                        }
                    }
                }

                if(clock_gettime(CLOCK_MONOTONIC, &(ipscan->entries[i].sent_time)) != 0) {
                    continue;
                    perror("clock_gettime");
                    return ERR_CLOCK;
                }
                ipscan->entries[i].state = SENT_ONCE;
                pthread_mutex_unlock((&ipscan->mutex));
                printf("sent 1 message!!\n");
                break;

            case SENT_ONCE:
                // if timeout time hass passes, resed tcp packet, open udp
                pthread_mutex_lock(&(ipscan->mutex));
                struct timespec current_time;
                if(clock_gettime(CLOCK_MONOTONIC, &current_time) != 0) {
                    perror("clock_gettime");
                    pthread_mutex_unlock(&(ipscan->mutex));     
                    return ERR_CLOCK;
                }
                long sec_to_ms = (current_time.tv_sec - ipscan->entries[i].sent_time.tv_sec) * 1000L;
                long ns_to_ms = (current_time.tv_nsec - ipscan->entries[i].sent_time.tv_nsec) / 1000000L;
                long time_sent = sec_to_ms + ns_to_ms;
                if(time_sent >= ipscan->timeout_time) {
                    if(ipscan->entries[i].protocol == UDP) {
                        ipscan->entries[i].state = OPEN;
                        ipscan->completed_entries++;
                    }

                    if(ipscan->entries[i].protocol == TCP) {
                        if(ipscan->address_family == AF_INET6) {
                            ipscan->target_ip.ipv6->sin6_port = htons(ipscan->entries[i].target_port);
                            if(sendto(ipscan->tcp_socket, &message, strlen(message), 0, (struct sockaddr*) ipscan->target_ip.ipv6, address_size)) {
                                perror("sendto");
                                pthread_mutex_unlock(&(ipscan->mutex));
                                return ERR_FAILURE;
                            }
                        }
                        else {
                            ipscan->target_ip.ipv4->sin_port = htons(ipscan->entries[i].target_port);
                            if(sendto(ipscan->tcp_socket, &message, strlen(message), 0, (struct sockaddr*) ipscan->target_ip.ipv6, address_size)) {
                                perror("sendto");
                                pthread_mutex_unlock(&(ipscan->mutex));
                                return ERR_FAILURE;
                            }
                        }

                        if(clock_gettime(CLOCK_MONOTONIC, &(ipscan->entries[i].sent_time))) {
                            perror("clock_gettime");
                            pthread_mutex_unlock(&(ipscan->mutex));
                            return ERR_CLOCK;
                        }
                        ipscan->entries[i].state = SENT_TWICE;
                    }
                }
                pthread_mutex_unlock(&(ipscan->mutex));
                break;
            case SENT_TWICE:
                pthread_mutex_lock(&(ipscan->mutex));
                ipscan->entries[i].state = FILTERED;
                ipscan->completed_entries++;
                pthread_mutex_unlock(&(ipscan->mutex));
                // tcp filtered
            break;
        
        }
    }
    return ERR_SUCCESS;
}


//needs refactoring
void* receive_messages(void* arg) {
    IPScanPtr scan = (IPScanPtr) arg;
    pcap_loop(scan->sniffer, -1, handle_packet, (unsigned char*) scan);
    return NULL;
}


void handle_packet(unsigned char* arg, const struct pcap_pkthdr* header, const unsigned char* packet) {
    IPScanPtr ipscan = (IPScanPtr) arg;
    int link_header_type = pcap_datalink(ipscan->sniffer);
    const unsigned char* ip_header_ptr;
    // eth 14 bytes
    if(link_header_type == DLT_EN10MB) {
        struct ether_header* eth_header = (struct ether_header*) packet;
        if(ntohs(eth_header->ether_type) != ETHERTYPE_IPV6 && ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
            return;
        } 
        ip_header_ptr = packet + 14; 
    }
    // lo 4 bytes
    else if(link_header_type == DLT_NULL || link_header_type == DLT_LOOP) {
        ip_header_ptr = packet + 4;
    }
    else {
        return;
    }
    // get ip version
    pthread_mutex_lock(&(ipscan->mutex));
    if((*ip_header_ptr) >> 4 == 4) {
        struct iphdr* ip_header = (struct iphdr*) ip_header_ptr;
        char ip_str[INET_ADDRSTRLEN];

        char src[INET_ADDRSTRLEN];
        char dst[INET_ADDRSTRLEN];

        if(ip_header->daddr != ipscan->source_ip.ipv4.s_addr || ip_header->saddr != ipscan->target_ip.ipv4->sin_addr.s_addr) {
            pthread_mutex_unlock(&(ipscan->mutex));
            return;
        }

        uint8_t protocol = ip_header->protocol;
        // handle tcp packet
        if(protocol == IPPROTO_TCP) {
            struct tcphdr* tcp_header =(struct tcphdr*) ((unsigned char*)ip_header + ip_header->ihl * 4);
            if(tcp_header->dest != SOURCE_PORT) {
                return;
            }

            ScanEntryPtr entry = find_entry(ipscan->entries, ipscan->entries_count, tcp_header->source, TCP);
            if(entry == NULL) {
                pthread_mutex_unlock(&(ipscan->mutex));
                return;
            }
            if(entry->state != SENT_ONCE && entry->state != SENT_TWICE) {
                pthread_mutex_unlock(&(ipscan->mutex));
                return;
            }
            if(tcp_header->rst) {
                entry->state = CLOSED;
            }
            else if(tcp_header->ack && tcp_header->syn) {
                entry->state = OPEN;
            }
            else {
                pthread_mutex_unlock(&(ipscan->mutex));
                return;
            }
            ipscan->completed_entries++;
            pthread_mutex_unlock(&(ipscan->mutex));
            return;
        }
        // handle udp packet (icmp message)
        else if(protocol == IPPROTO_ICMP){
            struct icmphdr* icmp_header = (struct icmphdr*) ((unsigned char*)ip_header + ip_header->ihl * 4);
            if(icmp_header->code != 3 || icmp_header->type != 3) {
                pthread_mutex_unlock(&(ipscan->mutex));
                return;
            }
            const unsigned char* orig_ip_header_ptr = (unsigned char*)(icmp_header + 1);
            struct iphdr* orig_ip_header = (struct iphdr*) orig_ip_header_ptr;
            if(orig_ip_header->daddr != ipscan->target_ip.ipv4->sin_addr.s_addr || orig_ip_header->saddr != ipscan->source_ip.ipv4.s_addr) {
                pthread_mutex_unlock(&(ipscan->mutex));
                return;
            }

            struct udphdr* udp_header = (struct udphdr*) ((unsigned char*)orig_ip_header + orig_ip_header->ihl * 4);


            ScanEntryPtr entry = find_entry(ipscan->entries, ipscan->entries_count, ntohs(udp_header->uh_dport), UDP);

            if(entry == NULL) {
                pthread_mutex_unlock(&(ipscan->mutex));
                return;
            }

            if(entry->state != SENT_ONCE) {
                pthread_mutex_unlock(&(ipscan->mutex));
                return;
            }
            entry->state = CLOSED;
            pthread_mutex_unlock(&(ipscan->mutex));
            ipscan->completed_entries++;
            return;
        }
    }
    else if((*ip_header_ptr) >> 4 == 6){
        struct ip6_hdr* ip_header = (struct ip6_hdr*) ip_header_ptr;
    }
    else {
        return;
    }

    pthread_mutex_unlock(&ipscan->mutex);
    return;
}