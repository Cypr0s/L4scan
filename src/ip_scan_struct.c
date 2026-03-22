/** -------------- IPK 1. project - L4 Scanner -----------------
 * @file    ip_scan_struct.c
 * @author  Kristian Luptak <xluptak00>
 * @date    creation:   18.3.2026
 *          updated:    22.3.2026
 * @brief   File contains every function that sets, resets or handles anything related
 *          to ipscan structure
 */


#include "ip_scan_struct.h"


/**
 * @def     ip_scan_ctor
 * @brief   creates default IPScan structure with basic parameters from scanner
 * @param   ipscan - ipscan struct which will be init
 * @param   scanner - scanner structure which holds important data which will be used in ipscan
 * @return  ERR_SUCCESS(0) setting default parameters was sucessful
 *          ERR_MALLOC(99) maloc failure
 *          ERR_PCAP(7) pcap open failure
 *          ERR_MUTEX(8) mutex creation failure
 */
ExitEnum ip_scan_ctor(IPScanPtr ipscan, ScannerPtr scanner) {
    // firstly try creating error prone things

    // 
    ipscan->entries = malloc(sizeof(ScanEntry) * (scanner->tcp_count + scanner->udp_count));
    if(ipscan->entries == NULL) {
        fprintf(stderr, "Malloc error\n");
        return ERR_MALLOC;
    }

    // create filter
    char errbuf[PCAP_ERRBUF_SIZE];
    ipscan->sniffer = pcap_open_live(scanner->interface_name, BUFSIZ, 0, 50, errbuf);
    if(ipscan->sniffer == NULL) {
        free(ipscan->entries);
        fprintf(stderr, "pcap_open_live error: %s\n", errbuf);
        return ERR_PCAP;
    }

    // create mutex for threads
    if(pthread_mutex_init(&(ipscan->mutex), NULL) != 0) {
        free(ipscan->entries);
        pcap_close(ipscan->sniffer);
        fprintf(stderr, "Mutex init error\n");
        return ERR_MUTEX;
    }

    // set default parameters
    create_scan_entries(scanner, ipscan->entries);
    ipscan->entries_count = scanner->tcp_count + scanner->udp_count;
    ipscan->timeout_time = scanner->timeout_time;
    ipscan->tcp_socket = -1;
    ipscan->udp_socket = -1;
    return ERR_SUCCESS;
} // ips_scan_ctor


/**
 * @def     ip_scan_dtor
 * @brief   frees everything allocated inside ipscan
 * @param   ipscan - ipscan struct which holds allocated data
 * @return  nothing
 */
void ip_scan_dtor(IPScanPtr ipscan) {
    if(ipscan->entries != NULL) {
        free(ipscan->entries);
    }
    if(ipscan->sniffer != NULL) {
        pcap_close(ipscan->sniffer);
    }
    pthread_mutex_destroy(&(ipscan->mutex));
}


/**
 * @def     create_scan_entries
 * @brief   creates all entries which will be used in scanning (this function is called only once)
 * @param   scanner - holds bitmaps of which entries need to be created
 * @param   entries - already allocated array which will hold the enries
 * @return  nothing (entries already has stored size of this array)
 */
void create_scan_entries(ScannerPtr scanner, ScanEntryPtr entries) {
    int entry_pos = 0;
    // loop from one to 65535 and creat entry if the bit is 1
    for(unsigned long i = 1; i <= MAX_PORTS; i++) {
        // tcp entry
        if(scanner->tcp_arr[i / LONG_BIT] & (1UL << (i % LONG_BIT))) {
            CREATE_ENTRY(entries, entry_pos, TCP, i);
            entry_pos++;
        }
        // udp entry
        if(scanner->udp_arr[i / LONG_BIT] & (1UL << (i % LONG_BIT))) {
            CREATE_ENTRY(entries, entry_pos, UDP, i);
            entry_pos++;
        }
    }
}


/**
 * @def     find_entry
 * @brief   finds one entry based on dest_port and protocol
 * @param   entries - array of ScanEntry structs
 * @param   entries_size - size of the array
 * @param   dest_port - destination port of entry
 * @param   proto - L4 protocol (UDP or TCP)
 * @return  pinter to entry struct or NULL if no entry was found
 */
ScanEntryPtr find_entry(ScanEntryPtr entries, int entries_size, 
                        unsigned short dest_port, ProtocolTypeEnum proto) {
    // loop through entries
    for(int i = 0; i < entries_size; i++) {
        if(entries[i].protocol == proto && entries[i].target_port == dest_port){
            return &entries[i];
        }
    }
    return NULL;
} // find_entry


/**
 * @def     set_filter
 * @brief   sets and compiles filter which is stored in ipscan based on address and information
 *          stored in scanner struct
 * @param   ipscan - stores the filter which needs to be set
 * @param   scanner - stores information about parameter flags (if udp tcp or both are needed)
 * @param   address - stores information about the type of address
 * @return  ERR_SUCCESS(0) no error, setting filter was successful
 *          ERR_FAILURE(1) default error (inet_ntop)
 *          ERR_PCAP(7) pcap libray errors (compile, setfilter)
 */
ExitEnum set_filter(IPScanPtr ipscan, ScannerPtr scanner, struct addrinfo* address) {
    char ip_string[INET6_ADDRSTRLEN];  // ip address as string
    char filter[128];  // created filter string

    // ipv4 address
    if(address->ai_family == AF_INET) {
        // create ip string from address
        if(inet_ntop(AF_INET, &((struct sockaddr_in*)address->ai_addr)->sin_addr, 
                        ip_string, sizeof(ip_string)) == NULL){
            perror("inet_ntop");
            return ERR_FAILURE;
        }
        
        // handle udp, tcp flags
        if(scanner->parameter_flags & TCP_FLG && scanner->parameter_flags & UDP_FLG) {
            snprintf(filter, sizeof(filter), 
                    "src host %s and (icmp or tcp dst port %d)", ip_string, SOURCE_PORT);
        }
        else if(scanner->parameter_flags & UDP_FLG && !(scanner->parameter_flags & TCP_FLG)) {
            snprintf(filter, sizeof(filter), "src host %s and icmp", ip_string);
        }
        else {
            snprintf(filter, sizeof(filter), 
                    "src host %s and tcp dst port %d", ip_string, SOURCE_PORT);
        }
    }
    // ipv6 address
    else {
        // create ipv6 string
        if(inet_ntop(AF_INET6, &((struct sockaddr_in6*)address->ai_addr)->sin6_addr, 
                        ip_string, sizeof(ip_string)) == NULL) {
            perror("inet_ntop");
            return ERR_FAILURE;
        }

        // handle parameters udp tcp
        if(scanner->parameter_flags & TCP_FLG && scanner->parameter_flags & UDP_FLG) {
            snprintf(filter, sizeof(filter), 
                    "src host %s and (icmp6 or tcp dst port %d)", ip_string, SOURCE_PORT);
        }
        else if(scanner->parameter_flags & UDP_FLG && !(scanner->parameter_flags & TCP_FLG)) {
            snprintf(filter, sizeof(filter), "src host %s and icmp6", ip_string);
        }
        else {
            snprintf(filter, sizeof(filter), 
                    "src host %s and tcp dst port %d", ip_string, SOURCE_PORT);
        }
    }

    // create filter
    struct bpf_program fp;
    if(pcap_compile(ipscan->sniffer, &fp, filter, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "pcap_compile error\n");
        return ERR_PCAP;
    }

    // actually set the filter
    if(pcap_setfilter(ipscan->sniffer, &fp) == -1) {
        fprintf(stderr, "pcap_setfilter error\n");
        return ERR_PCAP;
    }
    pcap_freecode(&fp); // free compiled
    return ERR_SUCCESS;
} // set_filter


/**
 * @def     set_sockets
 * @brief   set correct scan sockets based on ip scan addres(needs to be called before set_address)
 *          it does not matter whether the sockets are -1 (not initialized) caller wont try to send
 *          through them if they are not initialized
 * @param   ipscan - ipscan struct which will store the sockets
 * @param   socks - stores all sockets
 * @return  nothing
 */
void set_sockets(IPScanPtr ipscan, SocketsPtr socks) {
    if(ipscan->address_family == AF_INET) {
        ipscan->tcp_socket = socks->tcp_ipv4_socket;
        ipscan->udp_socket = socks->udp_ipv4_socket;
    }
    else {
        ipscan->tcp_socket = socks->tcp_ipv6_socket;
        ipscan->udp_socket = socks->udp_ipv6_socket;
    }
} // set_sockets


/**
 * @def     set_address
 * @brief   sets correct address and interface to ipscan struct
 * @param   ipscan - strcut which will hold addresses for scanning
 * @param   address - hold address which will scanned
 * @param   scanner - holds interface addresses from which scans entrys
 * @return  nothing
 */
void set_address(IPScanPtr ipscan, struct addrinfo* address, ScannerPtr scanner) {
    ipscan->address_family = address->ai_family;
    // ipv4
    if(ipscan->address_family == AF_INET) {
        ipscan->target_ip.ipv4 = (struct sockaddr_in*) address->ai_addr;
        ipscan->source_ip.ipv4 = scanner->interface_ipv4;
    }
    // ipv6
    else {
        ipscan->target_ip.ipv6 = (struct sockaddr_in6*) address->ai_addr;
        ipscan->source_ip.ipv6 = scanner->interface_ipv6;
    }
} // set_address
