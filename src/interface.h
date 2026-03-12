#ifndef INTERFACE_H
#define INTERFACE_H
#include "error.h"      // ExitEnum, errno
#include "parse.h"      // Scanner structure
#include <ifaddrs.h>    // getifaddr, freeifaddr
#include <stdio.h>      // prints, stdio
#include <net/if.h>     // IFF_UP
#include <string.h>     // strcmp

ExitEnum print_interfaces(const char* input);

#endif