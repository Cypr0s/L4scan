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
	// print interfaces and return
    if(scanner.interface_name != NULL) {
        print_interfaces();
        return ERR_SUCCESS;
    }

    struct addrinfo* addresses;
    ExitEnum err = get_addresses_from_hostname(scanner.hostname, &addresses, &scanner);
    if(err) {
        return err;
    }

    // get the FIRST address ipv4 interface or/and ipv6 interface
    ExitEnum err = get_interfaces(&scanner);
    if(err) {
        freeaddrinfo(addresses);
        return err;
    }

    // handle hostname (get ips from hostname), store them in addrinfo structs, 
	// store types of ip versions in scanner which will be further used for sockets, ..

    // create sockets, bind them to correct interfaces
	Sockets socks;
	if(create_sockets(&scanner, &socks)) {
		freeaddrinfo(addresses);
		destroy_sockets(&socks);
		return ERR_SOCKET;
	}

    // do the scanning
    err = scan_ipaddresses(&scanner, addresses, &socks);
    if(err) {
        return err;
    }


	destroy_sockets(&socks); // free sockets
	freeaddrinfo(addresses); // free addresses
    return ERR_SUCCESS;
}


ExitEnum debug_print(ScannerPtr scanner) {
    fprintf(stdout, "HOSTNAME: %s\n", scanner->hostname);
    if(scanner->parameter_flags & INTERFACE_FLG) {
        if(scanner->interface_name == NULL) {
           fprintf(stdout, "INTERFACE: ALL\n"); 
        }
        else {
            fprintf(stdout, "INTERFACE: %s\n", scanner->interface_name);
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