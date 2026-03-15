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
ExitEnum print_interfaces(const char* input) {
    struct ifaddrs* interfaces; // linked list of interfaces

    if(getifaddrs(&interfaces) == -1) {
        perror("getifaddrs");
        return ERR_GETIFADDRS;
    }

    // loop through all interfaces
    for(struct ifaddrs* ptr = interfaces; ptr != NULL; ptr = ptr->ifa_next){
        if(ptr->ifa_name == NULL || ptr->ifa_addr == NULL) { // show only active ones
            continue;
        }

        // input value provided (check if theres interface with that name)
        if(input != NULL) {
            if(!strcmp(input, ptr->ifa_name)) {
                return ERR_SUCCESS;
            }
        }
        // no value provided print all interfaces
        else {
            // print only once each
            if(ptr->ifa_addr->sa_family == AF_PACKET) {
                fprintf(stdout, "%s\n", ptr->ifa_name);
            }
        }  
    }
    // free interfaes
    freeifaddrs(interfaces);

    // check if there was atleast one interface if name was provided
    if(input != NULL) {
        fprintf(stderr, "`%s` is not a valid interface\n", input);
        return ERR_INVALID_ARGUMENT;
    }
    return ERR_SUCCESS;
} // print_interfaces


