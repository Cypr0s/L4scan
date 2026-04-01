/** -------------- IPK 1. project - L4 Scanner -----------------
 * @file    interface.c
 * @author  Kristian Luptak <xluptak00>
 * @date    creation:   12.3.2026
 *          updated:    22.3.2026
 * @brief   File handles anything related to interface
 *          argument, storing interface structs or
 *          printing all computer interfaces
 */


#include "interface.h"


/** 
 * @def     print_interfaces
 * @brief   prints all avaiable interfaces
 * @return  ERR_SUCCESS(0) no errors
 *          ERR_GETIFADDRS(3) getifaddrs error
 */
ExitEnum print_interfaces(void) {
    struct ifaddrs* interfaces;
    if(getifaddrs(&interfaces) == -1) {
        perror("getifaddrs");
        return ERR_GETIFADDRS;
    }

    // loop through all interfaces
    for(struct ifaddrs* ptr = interfaces; ptr != NULL; ptr = ptr->ifa_next){
        if(ptr->ifa_name == NULL || ptr->ifa_addr == NULL ) { // show only active ones
            continue;
        }

        int printed = 0;
        for (struct ifaddrs* temp = interfaces; temp != ptr; temp = temp->ifa_next) {
            if (temp->ifa_name != NULL && temp->ifa_addr != NULL &&
                strcmp(temp->ifa_name, ptr->ifa_name) == 0) {
                printed = 1;
                break;
            }
        }

        if (!printed) {
            fprintf(stdout, "%s\n", ptr->ifa_name);
        }
    }
    freeifaddrs(interfaces);
    return ERR_SUCCESS;
} // print_interfaces


/** @def    get_interfaces
 *  @brief  resolves interfaces from provided interface name and stores 
 *          2 ipv4/6 structs inside scanner (ipv6 global interface)
 *  @param  scanner - stores interface name, and will store ipv4 and/or ipv6 interface
 *  @return ERR_SUCCESS(0) when no errors happen
 *          ERR_GETIFADDRS(3) getifaddrs error
 *          ERR_NO_INTERFACE(4) when address needs ipv4/ipv6 interface and it was not found
 *                              or no interface at all was found
 */
ExitEnum get_interfaces(ScannerPtr scanner) {
    struct ifaddrs* interfaces;

    // resolve interfaces for provided interfae
    if(getifaddrs(&interfaces) == -1) {
        perror("getifaddrs");
        return ERR_GETIFADDRS;
    }

    struct in6_addr check = {0}; // util to check if scaner->ipv6 i empty

    // loop through interfaces
    for(struct ifaddrs* ptr = interfaces; ptr != NULL; ptr = ptr->ifa_next){
        if(ptr->ifa_name == NULL || ptr->ifa_addr == NULL) { // show only active ones
            continue;
        }
        if(strcmp(ptr->ifa_name, scanner->interface_name)) { // only the ones with the same name
            continue;
        }

        // ipv4
        if(ptr->ifa_addr->sa_family == AF_INET) {
            // check if it was already set
            if(scanner->interface_ipv4.s_addr != 0) {
                continue;
            }
            scanner->interface_ipv4 =  ((struct sockaddr_in*)ptr->ifa_addr)->sin_addr;
        }

        // ipv6
        if(ptr->ifa_addr->sa_family == AF_INET6) {
            // check if it was already set
            if(memcmp(&scanner->interface_ipv6, &check, sizeof(struct in6_addr)) != 0) {
                continue;
            }

            // check for loopback and link local
            struct sockaddr_in6* address = (struct sockaddr_in6*) ptr->ifa_addr;
            if(scanner->address_flag == ADDR_LOOPBACK && IN6_IS_ADDR_LOOPBACK(&address->sin6_addr)) {
                scanner->interface_ipv6 = ((struct sockaddr_in6*)ptr->ifa_addr)->sin6_addr;
            }
            else if (scanner->address_flag == ADDR_LINKLOCAL && 
                    IN6_IS_ADDR_LINKLOCAL(&address->sin6_addr)) 
            {
                scanner->interface_ipv6 = ((struct sockaddr_in6*)ptr->ifa_addr)->sin6_addr;
            }
            else if(scanner->address_flag == ADDR_GLOBAL && 
                    !IN6_IS_ADDR_LINKLOCAL(&address->sin6_addr) && 
                    !IN6_IS_ADDR_LOOPBACK(&address->sin6_addr)) 
            {
                scanner->interface_ipv6 = address->sin6_addr;
            }
        }
    } // for

    // free interfaces
    freeifaddrs(interfaces);

    // both interface are not set (err)
    if(memcmp(  &scanner->interface_ipv6, &check, sizeof(struct in6_addr)) == 0 && 
                scanner->interface_ipv4.s_addr == 0) 
    {
        fprintf(stderr, "No valid interfaces found to name `%s`\n", scanner->interface_name);
        return ERR_NO_INTERFACE;
    }

    // ipv4 address was found but no interface
    if(scanner->parameter_flags & IPV4_FLG && scanner->interface_ipv4.s_addr == 0) {
        fprintf(stderr, 
                "Hostname has ipv4 required to check but `%s` has no ipv4 interface\n", 
                scanner->interface_name
            );
        return ERR_NO_INTERFACE;
    }

    // ipv6 address was found but no interface
    if( scanner->parameter_flags & IPV6_FLG && 
        memcmp(&scanner->interface_ipv6, &check, sizeof(struct in6_addr)) == 0) 
    {
        fprintf(stderr, 
                "Hostname has ipv6 required to check but `%s` has no ipv4 interface\n", 
                scanner->interface_name
            );
        return ERR_NO_INTERFACE; 
    }

    return ERR_SUCCESS;  
} // get_interfaces


