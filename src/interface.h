/** -------------- IPK 1. project - L4 Scanner -----------------
 * @headerfile  interface.h
 * @author      Kristian Luptak <xluptak00>
 * @date        creation:   12.3.2026
 *              updated:    15.3.2026
 * @brief       Header file contains declaration of funcions used in interface.c
 */


#ifndef INTERFACE_H
#define INTERFACE_H


#include "error.h"      // ExitEnum, errno
#include "parse.h"      // Scanner structure
#include <ifaddrs.h>    // getifaddr, freeifaddr
#include <stdio.h>      // prints, stdio

ExitEnum get_interfaces(ScannerPtr scanner);

#endif // INTERFACE_H