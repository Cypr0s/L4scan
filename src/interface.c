#include "interface.h"

ExitEnum print_interfaces(const char* input) {
    struct ifaddrs* interfaces;;
    if(getifaddrs(&interfaces) == -1) {
        perror("getifaddrs");
        return ERR_GETIFADDRS;
    }
    // loop through all interfaces
    for(struct ifaddrs* ptr = interfaces; ptr != NULL; ptr = ptr->ifa_next){
        if(ptr->ifa_name == NULL || ptr->ifa_addr == NULL) { // show only active ones
            continue;
        }
        if(input != NULL) {
            if(!strcmp(input, ptr->ifa_name)) {
                return ERR_SUCCESS;
            }
        }
        else {
            // print only once each
            if(ptr->ifa_addr->sa_family == AF_PACKET) {
                fprintf(stdout, "%s\n", ptr->ifa_name);
            }
        }  
    }

    freeifaddrs(interfaces);

    if(input != NULL) {
        fprintf(stderr, "`%s` is not a valid interface\n", input);
        return ERR_INVALID_ARGUMENT;
    }
    return ERR_SUCCESS;
}


