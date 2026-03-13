#include "l4scan.h"

ExitEnum debug_print(ScannerPtr scanner);

int main(int argc, char** argv) {
    // handle input arguments
    Scanner scanner = {0};
    if(parse_arguments(argc, argv, &scanner)) {
        return ERR_INVALID_ARGUMENT;
    }
   
    if(scanner.parameter_flags & HELP_FLG) {
        return ERR_SUCCESS;
    }

    debug_print(&scanner);
    // handle -i parameter
    if(scanner.interface == NULL) {
        print_interfaces(NULL);
        return ERR_SUCCESS;
    }
    else {
        if(print_interfaces(scanner.interface)) {
            return ERR_INVALID_ARGUMENT;
        }
    }
    // handle hostname (get ips from hostname)
    struct addrinfo* adresses;
    ExitEnum err = get_addresses_from_hostname(scanner.hostname, &adresses);
    if(err) {
        return err;
    }

    return ERR_SUCCESS;
}

ExitEnum debug_print(ScannerPtr scanner) {
    fprintf(stdout, "HOSTNAME: %s\n", scanner->hostname);
    if(scanner->parameter_flags & INTERFACE_FLG) {
        if(scanner->interface == NULL) {
           fprintf(stdout, "INTERFACE: ALL\n"); 
        }
        else {
            fprintf(stdout, "INTERFACE: %s\n", scanner->interface);
        }
    }
    else {
        fprintf(stdout, "INTERFACE: NULL\n");
    }
    fprintf(stdout, "TIMEOUT: %d\n", scanner->timeout_time);

    for(unsigned long i = 1; i < USHRT_MAX + 1; i++) {
        if(scanner->tcp_arr[i / LONG_BIT] & (1UL << (i % LONG_BIT))) {
            fprintf(stdout, "TCP PORT: %lu\n", i);
        }
    }

    for(unsigned long i = 1; i < USHRT_MAX + 1; i++) {
        if(scanner->udp_arr[i / LONG_BIT] & (1UL << (i % LONG_BIT))) {
            fprintf(stdout, "UDP PORT: %lu\n", i);
        }
    }
    return ERR_SUCCESS;
}