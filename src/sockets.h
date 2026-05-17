/** -------------- L4scan -----------------
 * @headerfile  sockets.h
 * @author      Kristian Luptak <xluptak00>
 * @date        creation:   15.3.2026
 *              updated:    15.3.2026
 * @brief       Header file contains Sockets structure which will hold sockets,
 *              definition of macros which help with handling sockets, declarations
 *              of functions used in sockets.c            
 */

#ifndef SOCKETS_H
#define SOCKETS_H

#define SOURCE_PORT 53653 // random number 

#include "error.h"  // ExitEnum, errno
#include "parse.h"  // Scanner struct
#include <sys/socket.h> // sockets
#include <unistd.h> // close

// closes socket if it has a viable file_desctriptor
#define CLOSE_SOCKET(socket) do {   \
    if(socket != -1) {              \
        close(socket);              \
    }                               \
} while(0)

// sockets struct
typedef struct {
    int tcp_ipv4_socket;
    int udp_ipv4_socket;
    int tcp_ipv6_socket;
    int udp_ipv6_socket;
} Sockets, *SocketsPtr;

ExitEnum create_sockets(SocketsPtr socks, ScannerPtr scanner);

ExitEnum bind_sockets(SocketsPtr socks, ScannerPtr scanner);

void init_sockets_struct(SocketsPtr socks);

void destroy_sockets(SocketsPtr socks);

#endif // SOCKETS_H
