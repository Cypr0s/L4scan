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
        if(inet_ntop(AF_INET6, &((struct sockaddr_in6*)address->ai_addr)->sin6_addr, ip_string, sizeof(ip_string)) == NULL) {
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
    pcap_freecode(&fp);
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
        if(inet_ntop(ipscan->address_family, &(ipscan->target_ip.ipv4->sin_addr), target_ip, sizeof(target_ip)) == NULL) {
            perror("inet_ntop");
            return ERR_FAILURE;
        }
    }
    else {
        if(inet_ntop(ipscan->address_family, &(ipscan->target_ip.ipv6->sin6_addr), target_ip, sizeof(target_ip)) == NULL) {
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


void create_ipv4_packet(IPScanPtr ipscan, unsigned char* buffer, unsigned short buffer_size, unsigned short dest_port) {

    memset(buffer, 0, buffer_size);

    struct iphdr* ipv4_header = (struct iphdr*) buffer;
    ipv4_header->id = htons(rand());
    ipv4_header->check = 0; // checksum
    ipv4_header->version = 4; // ipv4 version
    ipv4_header->ihl = 5; // 20 bytes
    ipv4_header->protocol = IPPROTO_TCP;    // protocol type
    ipv4_header->saddr = ipscan->source_ip.ipv4.s_addr; // source ip (interface ipv4)
    ipv4_header->daddr = ipscan->target_ip.ipv4->sin_addr.s_addr;   // dest ip (hostname target ipv4)
    ipv4_header->ttl = 64; // 64 hops
    ipv4_header->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr)); // total size
    create_tcp_header(buffer + sizeof(struct iphdr), dest_port);
    compute_tcp_ipv4_checksum(ipv4_header,(struct tcphdr*) (buffer + sizeof(struct iphdr)));
    ipv4_header->check = checksum(buffer, sizeof(struct iphdr));
}

void create_tcp_header(unsigned char* buffer, unsigned short dest_port) {
    struct tcphdr* tcp_header = (struct tcphdr*) buffer;
    tcp_header->syn = 1; // sending SYN TCP packets
    tcp_header->source = htons(SOURCE_PORT);
    tcp_header->dest = htons(dest_port);
    tcp_header->seq = htonl(rand());
    tcp_header->check = 0;
    tcp_header->doff = 5;
}

// implementation inspired by https://www.packetmania.net/en/2021/12/26/IPv4-IPv6-checksum/
void compute_tcp_ipv4_checksum(struct iphdr* ipv4_header, struct tcphdr* tcp_header) {
    struct pseudo_header_v4 pseudo_header = {0};
    pseudo_header.src = ipv4_header->saddr;
    pseudo_header.dst = ipv4_header->daddr;
    pseudo_header.protocol = IPPROTO_TCP;
    pseudo_header.tcp_len  = htons(sizeof(struct tcphdr));

    char tmp[sizeof(struct pseudo_header_v4) + sizeof(struct tcphdr)];
    memcpy(tmp, &pseudo_header, sizeof(struct pseudo_header_v4));
    memcpy(tmp + sizeof(struct pseudo_header_v4), tcp_header, sizeof(struct tcphdr));

    tcp_header->check = checksum((unsigned char*)tmp, sizeof(tmp));
}


void create_ipv6_packet(IPScanPtr ipscan,unsigned char* buffer, unsigned short buffer_size, unsigned short dest_port) {
    memset(buffer, 0, buffer_size);

    struct ip6_hdr* ipv6_header = (struct ip6_hdr*) buffer;
    ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_flow = htonl((6 << 28));  // version 6
    ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_plen = htons(sizeof(struct tcphdr)); // "payload" size of headers after ipv6
    ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_nxt = IPPROTO_TCP; // next header
    ipv6_header->ip6_ctlun.ip6_un1.ip6_un1_hlim = 64;    // hops
    memcpy(&ipv6_header->ip6_src, &ipscan->source_ip.ipv6, sizeof(struct in6_addr));
    memcpy(&ipv6_header->ip6_dst, &ipscan->target_ip.ipv6->sin6_addr, sizeof(struct in6_addr));
    create_tcp_header(buffer + sizeof(struct ip6_hdr), dest_port);
    compute_tcp_ipv6_checksum(ipv6_header, (struct tcphdr*) (buffer + sizeof(struct ip6_hdr)));
}


// implementation inspired by https://www.packetmania.net/en/2021/12/26/IPv4-IPv6-checksum/
void compute_tcp_ipv6_checksum(struct ip6_hdr* ipv6_header, struct tcphdr* tcp_header) {
    struct pseudo_header_v6 pseudo_header = {0};
    memcpy(&pseudo_header.src, &ipv6_header->ip6_src, sizeof(struct in6_addr));
    memcpy(&pseudo_header.dst, &ipv6_header->ip6_dst, sizeof(struct in6_addr));
    pseudo_header.tcp_len = htonl(sizeof(struct tcphdr));
    pseudo_header.next_header = IPPROTO_TCP;

    char tmp[sizeof(struct pseudo_header_v6) + sizeof(struct tcphdr)];
    memcpy(tmp, &pseudo_header, sizeof(struct pseudo_header_v6));
    memcpy(tmp + sizeof(struct pseudo_header_v6), tcp_header, sizeof(struct tcphdr));

    tcp_header->check = checksum((unsigned char*)tmp, sizeof(tmp));
}
// implementation taken from https://www.packetmania.net/en/2021/12/26/IPv4-IPv6-checksum/ and formatted little bit
/* Compute Internet Checksum for "count" bytes, beginning at location "addr".*/
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
}
