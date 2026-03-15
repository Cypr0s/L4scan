/** -------------- IPK 1. project - L4 Scanner -----------------
 * @file    l4scan.c
 * @author  Kristian Luptak <xluptak00>
 * @date    creation:   11.3.2026
 *          updated:    15.3.2026
 * @brief   File handles the input of program (main function), calls corresponding
 * 			modules to handle, input arguments, and handles the whole program flow.
 */


#include "l4scan.h"

ExitEnum debug_print(ScannerPtr scanner);

/**
 * @def main
 * @brief entry and exit point of progam
 */
int main(int argc, char** argv) {
    Scanner scanner = {0};

	// handle input arguments
    if(parse_arguments(argc, argv, &scanner)) {
        return ERR_INVALID_ARGUMENT;
    }
	// help message flag, return with exit code 0
    if(scanner.parameter_flags & HELP_FLG) {
        return ERR_SUCCESS;
    }

    // handle -i parameter
	// Check if corresponding interface exists or print interfaces and return
    if(scanner.interface != NULL && print_interfaces(scanner.interface)) {
		return ERR_INVALID_ARGUMENT;
    }
    else {
        print_interfaces(NULL);
        return ERR_SUCCESS;
    }

    // handle hostname (get ips from hostname), store them in addrinfo structs, 
	// store types of ip versions in scanner which will be further used for sockets, ..
    struct addrinfo* addresses;
    ExitEnum err = get_addresses_from_hostname(scanner.hostname, &addresses, &scanner);
    if(err) {
        return err;
    }
	Sockets socks;
	if(create_sockets(&scanner, &socks)) {
		freeaddrinfo(addresses);
		destroy_sockets(&socks);
		return ERR_SOCKET;
	}

	destroy_sockets(&socks);
	freeaddrs(addresses); // free allocated structs
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

