/** -------------- IPK 1. project - L4 Scanner -----------------
 * @file    util.c
 * @author  Kristian Luptak <xluptak00>
 * @date    creation:   15.3.2026
 *          updated:    22.3.2026
 * @brief   utility functions   
 */


#include "util.h"


/**
 * @def     print_formated
 * @brief   prints formated string in stdout
 * @param   self explanatory
 */
void print_formated(char* ip_adress, unsigned short port_number, char* protocol, char* status) {
    fprintf(stdout,"%s %d %s %s", ip_adress, port_number, protocol, status);
} // print_formated


/**
 * @def     print_entry_states
 * @brief   prints state of each entry onto stdou and resets them for next scanning
 * @param   ipscan - contains the address for printing and all entries
 * @return  ERR_SUCCESS(0) no errors
 *          ERR_FAILURE(1) init_ntop error
 */
ExitEnum print_entry_states(IPScanPtr ipscan) {
    // print port states
    char target_ip[46];
    if(ipscan->address_family == AF_INET) {
        if(inet_ntop(ipscan->address_family, &(ipscan->target_ip.ipv4->sin_addr), 
                    target_ip, sizeof(target_ip)) == NULL) {
            perror("inet_ntop");
            return ERR_FAILURE;
        }
    }
    else {
        if(inet_ntop(ipscan->address_family, &(ipscan->target_ip.ipv6->sin6_addr), 
                    target_ip, sizeof(target_ip)) == NULL) {
            perror("inet_ntop");
            return ERR_FAILURE;
        }
    }
    // loop through ports print and reset each one
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
        // reset to default state
        ipscan->entries[i].state = WAITING;
        ipscan->entries[i].sent_time.tv_nsec = 0;
    }
    return ERR_SUCCESS;
} // print_entry_states


/**
 * @def     create_ipv4_packet
 *          inspired by:
 *          https://austinmarton.wordpress.com/2011/09/14/sending-raw-ethernet-packets-from-a-specific-interface-in-c-on-linux/
 * @brief   construct ipv4 header, tcp header and compute checksum for both
 * @param   ipscan - contains source and dest address
 * @param   buffer - buffer in which the packet will be stored
 * @param   buffer_size - size of buffer
 * @param   dest_port - destination tcp port
 */
void create_ipv4_packet(IPScanPtr ipscan, unsigned char* buffer, 
                        unsigned short buffer_size, unsigned short dest_port) {

    memset(buffer, 0, buffer_size);

    struct iphdr* ipv4_header = (struct iphdr*) buffer; // convert buffer to struct

    ipv4_header->id = htons(rand()); // random id
    ipv4_header->check = 0; // checksum
    ipv4_header->version = 4; // ipv4 version
    ipv4_header->ihl = 5; // 20 bytes
    ipv4_header->protocol = IPPROTO_TCP;    // protocol type
    ipv4_header->saddr = ipscan->source_ip.ipv4.s_addr; // source ip (interface ipv4)
    ipv4_header->daddr = ipscan->target_ip.ipv4->sin_addr.s_addr;   // dest ip (ipv4 taget)
    ipv4_header->ttl = 64; // 64 hops
    ipv4_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr)); // total size

    create_tcp_header(buffer + sizeof(struct iphdr), dest_port); // create tcp header
    compute_tcp_ipv4_checksum(ipv4_header,(struct tcphdr*) (buffer + sizeof(struct iphdr)));
    ipv4_header->check = checksum(buffer, sizeof(struct iphdr));
} // create_ipv4_packet


/**
 * @def     create_tcp_header
 * @brief   creates SYN tcp header which will be sent
 * @param   buffer - already created ip buffer which will hold tcp header
 * @param   dest_port - destnation port of header
 * @return  nothing 
 */
void create_tcp_header(unsigned char* buffer, unsigned short dest_port) {
    struct tcphdr* tcp_header = (struct tcphdr*) buffer;
    tcp_header->syn = 1; // sending SYN TCP packets
    tcp_header->source = htons(SOURCE_PORT);    // source port
    tcp_header->dest = htons(dest_port);    // destination port
    tcp_header->seq = htonl(rand());    // random seq
    tcp_header->check = 0;      //checksum
    tcp_header->doff = 5;   // basic offset size
    tcp_header->window = htons(1024); // window size
} // create_tcp_header


/**
 * @def     compute_tcp_ipv4_checksum
 *          // implementation inspired by https://www.packetmania.net/en/2021/12/26/IPv4-IPv6-checksum/
 * @brief   computes tcp header ipv4 checksum with pseudoheader
 * @param   ipv4_header - ipv4 header struct (filled)
 * @param   tcp_header - tcp_header struct (filled)
 */
void compute_tcp_ipv4_checksum(struct iphdr* ipv4_header, struct tcphdr* tcp_header) {
    struct pseudo_header_v4 pseudo_header = {0};

    // init pseudo header
    pseudo_header.src = ipv4_header->saddr;
    pseudo_header.dst = ipv4_header->daddr;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_len  = htons(sizeof(struct tcphdr));

    char tmp[sizeof(struct pseudo_header_v4) + sizeof(struct tcphdr)];

    // copy pesudo header, tcp header
    memcpy(tmp, &pseudo_header, sizeof(struct pseudo_header_v4));
    memcpy(tmp + sizeof(struct pseudo_header_v4), tcp_header, sizeof(struct tcphdr));

    tcp_header->check = checksum((unsigned char*)tmp, sizeof(tmp)); // checksum
} // compute_tcp_ipv4_checksum


/**
 * @def     compute_tcp_ipv6_checksum
 *          implementation inspired by https://www.packetmania.net/en/2021/12/26/IPv4-IPv6-checksum/
 * @brief   computes checksum for tcp header ipv6 addresses
 * @param   tcp_header - tcp header which needs checksum
 * @param   ipscan - contains source and dest ipv6s
 */
void compute_tcp_ipv6_checksum(struct tcphdr* tcp_header, IPScanPtr ipscan) {
    struct pseudo_header_v6 pseudo_header = {0};
    memcpy(&pseudo_header.src, &ipscan->source_ip.ipv6, sizeof(struct in6_addr)); // copy ipv6 src
    memcpy(&pseudo_header.dst, &ipscan->target_ip.ipv6->sin6_addr, sizeof(struct in6_addr)); // copy ipv6 dst

    pseudo_header.tcp_len = htonl(sizeof(struct tcphdr));
    pseudo_header.next_header = IPPROTO_TCP;

    char tmp[sizeof(struct pseudo_header_v6) + sizeof(struct tcphdr)];
    // copy pseudo header and tcp header
    memcpy(tmp, &pseudo_header, sizeof(struct pseudo_header_v6));
    memcpy(tmp + sizeof(struct pseudo_header_v6), tcp_header, sizeof(struct tcphdr));

    tcp_header->check = checksum((unsigned char*)tmp, sizeof(tmp)); // checksum
} // compute_tcp_ipv6_checksum


/**
 * @def     checksum
 *          implementation taken from https://www.packetmania.net/en/2021/12/26/IPv4-IPv6-checksum/ 
 *          and formatted little bit
 * @brief   Compute Internet Checksum for "count" bytes, beginning at location "addr
 */
unsigned short checksum(unsigned char* addr , int count) {
    /* Compute Internet Checksum for "count" bytes, beginning at location "addr".*/
    register long sum = 0;

    while( count > 1 )  {
        /*  This is the inner loop */
        sum += * (unsigned short*) addr;
        addr += 2;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if(count > 0) {
        sum += * (unsigned char *) addr;
    }

    /*  Fold 32-bit sum to 16 bits */
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    return (unsigned short) (~sum);
} // checksum


/**
 * @def     check_timeout
 * @brief   finds the time that passed since entry was sent and stores it into val
 * @param   entry - holds sent time timespect struct
 * @param   val - in this the time will be stored in ms
 * @return  ERR_SUCCESS(0) no erros
 *          ERR_CLOCK(9) clock_gettime error
 */
ExitEnum check_timeout(ScanEntryPtr entry, long* val) {
    struct timespec current_time;
    if(clock_gettime(CLOCK_MONOTONIC, &current_time) != 0) {
        perror("clock_gettime");    
        return ERR_CLOCK;
    }

    long sec_to_ms = (current_time.tv_sec - entry->sent_time.tv_sec) * 1000L;
    long ns_to_ms = (current_time.tv_nsec - entry->sent_time.tv_nsec) / 1000000L;
    long time_sent = sec_to_ms + ns_to_ms;
    *val = time_sent;
    return ERR_SUCCESS;
}  // check_timeout


/**
 * @def     send_entry
 * @brief   sends entry to ip addres destination and sets timeout timer and sets new state for
 *          entry
 * @param   message - pointer to packer or message to be sent
 * @param   message_size - size of message
 * @param   socket - valid fd of socket
 * @param   entry - entry ScanEntry ptr struct
 * @param   address - target address
 * @param   address_size - correct addres size
 * @return  ERR_SUCCESS(0) - no error
 *          ERR_CLOCK(0) - clock_gettime err
 *          ERR_SOCKET(0) - sendto err 
 */
ExitEnum send_entry(unsigned char* message, unsigned short message_size, int socket, 
                    ScanEntryPtr entry, struct sockaddr* address, unsigned address_size)
{   
    // send message
    if(sendto(socket, message, message_size, 0, address, address_size) < 0) {
        perror("sendto");
        return ERR_SOCKET;
    }

    // set timer
    if(clock_gettime(CLOCK_MONOTONIC, &(entry->sent_time)) != 0) {
        perror("clock_gettime");
        return ERR_CLOCK;
    }

    // set state
    entry->state++; // WAITING->SENT_ONCE->SENT_TWICE

    return ERR_SUCCESS;
} // send_entry


/**
 * @def     handle_ipv6_header
 * @brief   handles ipv6 header and calls next header handling function based on next protocol
 * @param   char_header - pointer to start of ipv6 header
 * @param   ipscan - contains source and destination ips for comparison
 */
void handle_ipv6_header(unsigned char* char_header, IPScanPtr ipscan) {
    struct ip6_hdr* ip_header = (struct ip6_hdr*) char_header;
    // compare their dst ==  our src
    if(memcmp(&ip_header->ip6_dst, &ipscan->source_ip.ipv6, sizeof(struct in6_addr)) != 0) {
        return;
    }
    // compare  their src == our dst
    if(memcmp(&ip_header->ip6_src, 
                &ipscan->target_ip.ipv6->sin6_addr, sizeof(struct in6_addr)) != 0) 
    {
        return;
    }
    uint8_t protocol = ip_header->ip6_ctlun.ip6_un1.ip6_un1_nxt;

    // check protocol
    if(protocol == IPPROTO_TCP) {
        handle_tcp_header(char_header + sizeof(struct ip6_hdr), ipscan);
    }
    else if (protocol == IPPROTO_ICMPV6)
    {
        handle_icmpv6_header(char_header + sizeof(struct ip6_hdr), ipscan);
    }
    else{
        return;
    }  
} // handle_ipv6_header


/**
 * @def     handle_tcp_header
 * @brief   handles tcp header and sets entry state to OPEN/ CLOSED
 * @param   char_header - pointer to start of tcp header
 * @param   ipscan - contains entries
 */
void handle_tcp_header(unsigned char* char_header, IPScanPtr ipscan) {
    struct tcphdr* tcp_header =(struct tcphdr*) char_header;
    // check if ports are eq their dst our source
    if(tcp_header->dest != htons(SOURCE_PORT)) {
        return;
    }
    // find entry
    ScanEntryPtr entry = find_entry(ipscan->entries, ipscan->entries_count, ntohs(tcp_header->source), TCP);
    if(entry == NULL) {
        return;
    }
    // check if its already completed
    if(entry->state != SENT_ONCE && entry->state != SENT_TWICE) {
        return;
    }
    // set state
    if(tcp_header->rst) {
        entry->state = CLOSED;
    }
    else if(tcp_header->ack && tcp_header->syn) {
        entry->state = OPEN;
    }
    else {
        return;
    }
    // inc completed
    ipscan->completed_entries++;
} // handle_tcp_header


/**
 * @def     handle_icmpv6_header
 * @brief   handles icmp6 header and sets corresponding entry state to CLOSED
 * @param   char_header - pointer to start of icmp6 header
 * @param   ipscan - contains entries
 */
void handle_icmpv6_header(unsigned char* char_header, IPScanPtr ipscan) {
    struct icmp6_hdr* icmp6_header = (struct icmp6_hdr*) char_header;
    // check valid response
    if(icmp6_header->icmp6_code != 4 || icmp6_header->icmp6_type != 1) {
        return;
    }
    // get orig ipv6 header
    unsigned char* orig_ipv6_header_ptr = char_header + sizeof(struct icmp6_hdr);
    struct ip6_hdr* orig_ipv6_header = (struct ip6_hdr*) orig_ipv6_header_ptr;
    
    // check our dst == their dst (orig header)
    if(memcmp(&orig_ipv6_header->ip6_dst, 
            &ipscan->target_ip.ipv6->sin6_addr, sizeof(struct in6_addr)) != 0) 
    {
        return;
    } 
    // check our src == their src (orig header)
    if(memcmp(&orig_ipv6_header->ip6_src, &ipscan->source_ip.ipv6, sizeof(struct in6_addr)) != 0) {
        return;
    }
    // get ORIG udp
    struct udphdr* udp_header = (struct udphdr*) (orig_ipv6_header_ptr + sizeof(struct ip6_hdr));

    if(udp_header->source != htons(SOURCE_PORT)) {
        return;
    }
    // find entry
    ScanEntryPtr entry = find_entry(ipscan->entries, 
                                    ipscan->entries_count, ntohs(udp_header->uh_dport), UDP);
    if(entry == NULL) {
        return;
    }

    // already done
    if(entry->state != SENT_ONCE) {
        return;
    }
    entry->state = CLOSED;
    ipscan->completed_entries++;
} // handle_icmpv6_header


/**
 * @def     handle_ipv4_header
 * @brief   handles ipv4 header and calls next header handling function based on next protocol
 * @param   char_header - pointer to start of ipv4 header
 * @param   ipscan - contains source and destination ips for comparison
 */
void handle_ipv4_header(unsigned char* char_header, IPScanPtr ipscan) {
    struct iphdr* ip_header = (struct iphdr*) char_header;
    // check src = dst , dst = src
    if(ip_header->daddr != ipscan->source_ip.ipv4.s_addr || 
        ip_header->saddr != ipscan->target_ip.ipv4->sin_addr.s_addr) 
    {
        return;
    }

    uint8_t protocol = ip_header->protocol;
    // check protocol
    if(protocol == IPPROTO_TCP) {
        handle_tcp_header(char_header + ip_header->ihl * 4, ipscan);
    }
    else if (protocol == IPPROTO_ICMP)
    {
        handle_icmp_header(char_header + ip_header->ihl * 4, ipscan);
    }
    else{
        return;
    }  
} // handle_ipv4_header


/**
 * @def     handle_icmp_header
 * @brief   handles icmp header and sets corresponding entry state to CLOSED
 * @param   char_header - pointer to start of icmp6 header
 * @param   ipscan - contains entries
 */
void handle_icmp_header(unsigned char* char_header, IPScanPtr ipscan) {
    struct icmphdr* icmp_header = (struct icmphdr*) char_header;
    if(icmp_header->code != 3 || icmp_header->type != 3) {
        return;
    }
    // get orig ip header
    unsigned char* orig_ip_header_ptr = char_header + sizeof(struct icmphdr);
    struct iphdr* orig_ip_header = (struct iphdr*) orig_ip_header_ptr;
    
    // check dst == dst , src == src
    if(orig_ip_header->daddr != ipscan->target_ip.ipv4->sin_addr.s_addr || 
        orig_ip_header->saddr != ipscan->source_ip.ipv4.s_addr) 
    {
        return;
    }

    // get orig udp header
    struct udphdr* udp_header = (struct udphdr*) 
                                ((unsigned char*)orig_ip_header + orig_ip_header->ihl * 4);

    if(udp_header->source != htons(SOURCE_PORT)) {
        return;
    }

    // find entry
    ScanEntryPtr entry = find_entry(ipscan->entries, 
                                    ipscan->entries_count, ntohs(udp_header->uh_dport), UDP);

    if(entry == NULL) {
        return;
    }

    if(entry->state != SENT_ONCE) {
        return;
    }
    
    entry->state = CLOSED;
    ipscan->completed_entries++;
} // handle_icmp_header
