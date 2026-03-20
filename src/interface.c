/** -------------- IPK 1. project - L4 Scanner -----------------
 * @file    interface.c
 * @author  Kristian Luptak <xluptak00>
 * @date    creation:   12.3.2026
 *          updated:    15.3.2026
 * @brief   File handles anything related to interface
 *          argument, checking if provided interface exists or
 *          printing all computer interfaces
 */


#include "interface.h"


/** 
 * @def     print_interfaces
 * @brief   Based on input either print all interfaces if input is NULL, 
 *          otherwise check if provided input exists
 * @param   input - name of the interface that needs to be check or NULL
 * @return  ERR_INVALID_ARGUMENT(2) if provided interface doesnt exist
 *          ERR_SUCCESS(0) if input is null and interfaces were printed or 
 *          provided interface exists
 */
ExitEnum print_interfaces(void) {
    struct ifaddrs* interfaces;
    if(getifaddrs(&interfaces) == -1) {
        perror("getifaddrs");
        return ERR_GETIFADDRS;
    }

    // loop through all interfaces
    for(struct ifaddrs* ptr = interfaces; ptr != NULL; ptr = ptr->ifa_next){
        if(ptr->ifa_name == NULL || ptr->ifa_addr == NULL) { // show only active ones
            continue;
        }

        // print only once each
        if(ptr->ifa_addr->sa_family == AF_PACKET) {
            fprintf(stdout, "%s\n", ptr->ifa_name);
        }  
    }
    freeifaddrs(interfaces);
    return ERR_SUCCESS;
} // print_interfaces


ExitEnum get_interfaces(ScannerPtr scanner) {
    struct ifaddrs* interfaces;
    struct in6_addr zero6 = IN6ADDR_ANY_INIT;

    if(getifaddrs(&interfaces) == -1) {
        perror("getifaddrs");
        return ERR_GETIFADDRS;
    }

    for(struct ifaddrs* ptr = interfaces; ptr != NULL; ptr = ptr->ifa_next){
        if(ptr->ifa_name == NULL || ptr->ifa_addr == NULL) { // show only active ones
            continue;
        }
        if(strcmp(ptr->ifa_name, scanner->interface_name)) {
            continue;
        }
        // print only once each
        if(ptr->ifa_addr->sa_family == AF_INET && scanner->interface_ipv4.s_addr == 0) {
            scanner->interface_ipv4 =  ((struct sockaddr_in*)ptr->ifa_addr)->sin_addr;
        }

        if(ptr->ifa_addr->sa_family == AF_INET6 && memcmp(&scanner->interface_ipv6, &zero6, sizeof(struct in6_addr)) == 0) {
            scanner->interface_ipv6 = ((struct sockaddr_in6*)ptr->ifa_addr)->sin6_addr;
        }  
    }
    freeifaddrs(interfaces);
    if(memcmp(&scanner->interface_ipv6, &zero6, sizeof(struct in6_addr)) == 0 && scanner->interface_ipv4.s_addr == 0) {
        fprintf(stderr, "No valid interfaces found to name `%s`\n", scanner->interface_name);
        return ERR_NO_INTERFACE;
    }

    if(scanner->parameter_flags & IPV4_FLG && scanner->interface_ipv4.s_addr == 0) {
        fprintf(stderr, "Hostname has ipv4 required to check but `%s` has no ipv4 interface\n", scanner->interface_name);
        return ERR_NO_INTERFACE;
    }

    if(scanner->parameter_flags & IPV6_FLG && memcmp(&scanner->interface_ipv6, &zero6, sizeof(struct in6_addr)) == 0) {
        fprintf(stderr, "Hostname has ipv6 required to check but `%s` has no ipv4 interface\n", scanner->interface_name);
        return ERR_NO_INTERFACE; 
    }

    return ERR_SUCCESS;  
} // get_interfaces


