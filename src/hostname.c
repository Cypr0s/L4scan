/** -------------- IPK 1. project - L4 Scanner -----------------
 * @file    hostname.c
 * @author  Kristian Luptak <xluptak00>
 * @date    creation:   12.3.2026
 *          updated:    22.3.2026
 * @brief   File handles anything related to hostname argument, 
 *          eg. get_addresses_from_hostname return struct of ips that
 *          are obtained from getaddrinfo()     
 */


#include "hostname.h"


/** 
 *  @def    get_addresses_from_hostname
 *  @brief  resolves all addresses from hostname and stores them in hostname_values,
 *          caller must call free, Stores flags if provided hostname contains ipv4 and/or ipv6 address
 *  @param  hostname_values - struct addrinfo which stores all ip addresses from hostname
 *  @param  scanner - which holds hostname name, will store ip flags
 *  @return ERR_SUCCESS(0) sucess
 *          ERR_INVALID_ARGUMENT(2) hostname was invalid
 *          ERR_HOSTNAME(4) getaddrinfo error
 */
ExitEnum get_addresses_from_hostname(struct addrinfo** hostname_values, ScannerPtr scanner) {
    struct addrinfo hints = {0};

    hints.ai_family = AF_UNSPEC;    //both ipv4 and ipv6 adresses
    hints.ai_socktype = SOCK_RAW;   // just one entry per address
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


/**
 * @def     scan_ip_addresses
 * @brief   scans each address and prints states for each port for each address
 * @param   scanner - holds parsed data which will be set into ipscan struct
 * @param   addreses - holds all addresses parsed from hostname inpust
 * @param   socks - hold iniatilized sockets
 * @return  ERR_SUCCES(0)
 *          many non error codes on error
 */
ExitEnum scan_ip_addresses(ScannerPtr scanner, struct addrinfo* addresses, SocketsPtr socks) {
    // init scanning struct
    IPScan ipscan = {0};
    ExitEnum err = ip_scan_ctor(&ipscan, scanner);
    if(err) {
        return err;
    }

    // loop through addresses
    for(struct addrinfo* addr_ptr = addresses; addr_ptr != NULL; addr_ptr = addr_ptr->ai_next) {

        //set ipscan parameters for the address
        set_filter(&ipscan, scanner, addr_ptr);
        set_address(&ipscan, addr_ptr, scanner);
        set_sockets(&ipscan, socks);

        // create 2 threads
        pthread_t send, receive;
        //send packets thread
        pthread_create(&send, NULL, send_messages, (void*) &ipscan);
        // receive packets thread
        pthread_create(&receive, NULL, receive_messages, (void*) &ipscan);
        void* return_val;
        pthread_join(send,&return_val);
        pthread_join(receive, NULL);
        err = (ExitEnum)(long) return_val;
        if(err) {
            ip_scan_dtor(&ipscan);
            return err;
        }

        // print entry states and reset entrys
        if(print_entry_states(&ipscan)) {
            ip_scan_dtor(&ipscan);
            return ERR_FAILURE;
        }
    }

    ip_scan_dtor(&ipscan); // free allocated memory
    return ERR_SUCCESS;
} // scan_ip_addresses


/**
 * @def     send_messages
 * @brief   function sends all entries inside while loop until all entries are completed
 * @param   arg holds ipscan ptr struct
 * @return  
 */
void* send_messages(void* arg) {
    IPScanPtr ipscan = (IPScanPtr) arg;
    ExitEnum err = ERR_SUCCESS;
    while(1) {
        // 
        if(status) {  // signal was caught
            pcap_breakloop(ipscan->sniffer);
            return(void*) ERR_SUCCESS;
        }
        //check if all are done
        pthread_mutex_lock(&(ipscan->mutex));
        if(ipscan->entries_count == ipscan->completed_entries) {
            pthread_mutex_unlock(&(ipscan->mutex));
            break;
        }
        pthread_mutex_unlock(&(ipscan->mutex));
        
        // send entries
        err = handle_messages_fsm(ipscan);
        if(err) {
            break;
        }
    }
    pcap_breakloop(ipscan->sniffer); // break receiver pcap loop
    return(void*) err;
} // send_messages


/**
 * @def     handle_messages_fsm
 * @brief   kinda FSM that decides what to do to each entry based on its state
 *          (either sends messages and sets theirs new states)
 * @param   ipscan - holds target address. mutex and all entries
 * @return  ERR_SUCESS(0) - no error
 *          ERR_SOCKET(5) - sendto failure
 *          ERR_CLOCK(9) - getting time failure 
 */
ExitEnum handle_messages_fsm(IPScanPtr ipscan) {
    unsigned int address_size = ipscan->address_family == AF_INET ? 
                        sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6);
    // loop through all entries
    for(int i = 0; i < ipscan->entries_count; i++) {
        switch(ipscan->entries[i].state) {
            // skip completed
            case OPEN: case CLOSED: case FILTERED:
                continue;
            
            case WAITING: {
                pthread_mutex_lock(&(ipscan->mutex));
                // tcp 
                struct sockaddr* target; // target addres
                unsigned short message_size;
                ExitEnum err; // error
                if(ipscan->entries[i].protocol == TCP) {
                    message_size = ipscan->address_family == AF_INET ?
                        sizeof(struct iphdr) + sizeof(struct tcphdr) :
                        sizeof(struct tcphdr);
                    unsigned char message[message_size];


                    // set target , create packet
                    if(ipscan->address_family == AF_INET) {
                        target = (struct sockaddr*) ipscan->target_ip.ipv4;
                        create_ipv4_packet(ipscan, message, message_size, 
                                            ipscan->entries[i].target_port);
                    }
                    else {
                        target = (struct sockaddr*) ipscan->target_ip.ipv6;
                        create_tcp_header(message, ipscan->entries[i].target_port);
                        compute_tcp_ipv6_checksum((struct tcphdr*) message, ipscan);
                    }
                    // send
                    err = send_entry(message, message_size, ipscan->tcp_socket, 
                                            &(ipscan->entries[i]), target, address_size);
                }
                // udp
                if(ipscan->entries[i].protocol == UDP) {
                    // udp message
                    unsigned char message[] = "sup udp\n";
                    message_size = sizeof(message);
                    
                    // use copies
                    struct sockaddr_in addr4_copy;
                    struct sockaddr_in6 addr6_copy;
                    // set target port and target
                    if(ipscan->address_family == AF_INET) {
                        addr4_copy = *ipscan->target_ip.ipv4;
                        addr4_copy.sin_port = htons(ipscan->entries[i].target_port);
                        target = (struct sockaddr*) &addr4_copy;
                    }
                    else{
                        addr6_copy = *ipscan->target_ip.ipv6;
                        addr6_copy.sin6_port = htons(ipscan->entries[i].target_port);
                        target = (struct sockaddr*) &addr6_copy;
                    }
                    // send entry
                    err = send_entry(message, message_size, ipscan->udp_socket, 
                                            &(ipscan->entries[i]), target, address_size);
                }
                // check err
                if(err) {
                    pthread_mutex_unlock((&ipscan->mutex));
                    return err;
                }

                pthread_mutex_unlock((&ipscan->mutex));
                break;
            } // case WAITING

            case SENT_ONCE: {
                // if timeout time has passed, resed tcp packet, open udp
                pthread_mutex_lock(&(ipscan->mutex));
                long time_sent;
                ExitEnum err = check_timeout(&(ipscan->entries[i]), &time_sent);
                if(err) {
                    pthread_mutex_unlock(&(ipscan->mutex));
                    return err;
                }
                // timeout passed
                if(time_sent >= ipscan->timeout_time) {
                    // udp is open(no response)
                    if(ipscan->entries[i].protocol == UDP) {
                        ipscan->entries[i].state = OPEN;
                        ipscan->completed_entries++;
                    }
                    // tcp resend
                    if(ipscan->entries[i].protocol == TCP) {
                        unsigned short message_size = ipscan->address_family == AF_INET ?
                        sizeof(struct iphdr) + sizeof(struct tcphdr) :
                        sizeof(struct tcphdr);
                        unsigned char message[message_size];

                        struct sockaddr* target; // target addres
                        // set target , create packet
                        if(ipscan->address_family == AF_INET) {
                            target = (struct sockaddr*) ipscan->target_ip.ipv4;
                            create_ipv4_packet(ipscan, message, message_size, 
                                                ipscan->entries[i].target_port);
                        }
                        else {
                            target = (struct sockaddr*) ipscan->target_ip.ipv6;
                            create_tcp_header(message, ipscan->entries[i].target_port);
                            compute_tcp_ipv6_checksum((struct tcphdr*) message, ipscan);
                        }
                        // send
                        err = send_entry(message, message_size, ipscan->tcp_socket, 
                                                &(ipscan->entries[i]), target, address_size);

                        if(err) {
                            pthread_mutex_unlock(&(ipscan->mutex));
                            return err;
                        } // err if
                    } // tcp if
                }   // if
                pthread_mutex_unlock(&(ipscan->mutex));
                break;
            } // case SENT_ONCE

            case SENT_TWICE: {
                pthread_mutex_lock(&(ipscan->mutex));
                // check timeout
                long time_sent;
                ExitEnum err = check_timeout(&(ipscan->entries[i]), &time_sent);
                if(err) {
                    pthread_mutex_unlock(&(ipscan->mutex));
                    return err;
                }
                // timeout passed
                if(time_sent >= ipscan->timeout_time) {
                    ipscan->entries[i].state = FILTERED;
                    ipscan->completed_entries++;
                }
                pthread_mutex_unlock(&(ipscan->mutex));
                // tcp filtered
                break;
            }
        } // switch
    } // for loop through entries
    return ERR_SUCCESS;
} // handle_messages_fsm


/**
 * @def     receive_messages
 * @brief   receiver thread pcap loop handler
 * @param   arg - IPScanPtr
 */
void* receive_messages(void* arg) {
    IPScanPtr ipscan = (IPScanPtr) arg;
    pcap_loop(ipscan->sniffer, -1, handle_packet, (unsigned char*) ipscan);
    return NULL;
}


/**
 * @def     handle_packet
 * @brief   function handles received packet and if its correct it 
 * @param   arg - ipscan struct
 * @param   header header metadata - not used here just casted to voidptr so complirer doesnt cry
 * @param   packet packet data
 */
void handle_packet(unsigned char* arg, const struct pcap_pkthdr* header, const unsigned char* packet) {
    (void) header;
    IPScanPtr ipscan = (IPScanPtr) arg;
    int link_header_type = pcap_datalink(ipscan->sniffer);
    const unsigned char* ip_header_ptr;
    // eth 14 bytes
    if(link_header_type == DLT_EN10MB) {
        struct ether_header* eth_header = (struct ether_header*) packet;
        // check ipv6 or ivp4
        if(ntohs(eth_header->ether_type) != ETHERTYPE_IPV6 && ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
            return;
        } 
        ip_header_ptr = packet + 14; 
    }
    // lo 4 bytes
    else if(link_header_type == DLT_NULL || link_header_type == DLT_LOOP) { // loopback // dlt
        ip_header_ptr = packet + 4;
    }
    else {
        return;
    }
    pthread_mutex_lock(&(ipscan->mutex));
    // handle ipv4
    if((*ip_header_ptr) >> 4 == 4) {
        handle_ipv4_header((unsigned char*) ip_header_ptr, ipscan);
    }
    // handle ipv6
    else {
        handle_ipv6_header((unsigned char*) ip_header_ptr, ipscan);
    }
    pthread_mutex_unlock(&(ipscan->mutex));
    return;
}