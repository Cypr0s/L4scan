#ifndef L4SCAN_H
#define L4SCAN_H

#include "parse.h"      // parsing, scanner struct
#include "hostname.h"   // hostname
#include "interface.h"  // interface
#include "sockets.h"    // sockets operations



ExitEnum debug_print(ScannerPtr scanner);

#endif // L4SCAN_H