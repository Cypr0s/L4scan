/** -------------- IPK 1. project - L4 Scanner -----------------
 * @file    sockets.c
 * @author  Kristian Luptak <xluptak00>
 * @date    creation:   15.3.2026
 *          updated:    15.3.2026
 * @brief   File handles anything related to sockets, like creating 
 *          them and destroying them        
 */

#include "sockets.h"

/**
 * @def     create_sockets
 * @brief   Create 4 different types of socket based on input from scanner struct, 
 *          assume caller frees allocated socket file descriptors
 * @param   scanner - pointer to scanner struct which holds information about which 
 *          sockets to create inside scanner->parameter_flags
 * @param   socks - pointer to Sockets 
 */
ExitEnum create_sockets(ScannerPtr scanner, SocketsPtr socks) {
    //ipv4 sockets
    if(scanner->parameter_flags & IPV4_FLG) {
        if(scanner->parameter_flags & TCP_FLG) {
            socks->tcp_ipv4_socket = socket(AF_INET, SOCK_RAW, 0);
            CHECK_SOCKET(socks->tcp_ipv4_socket);
        }

        if(scanner->parameter_flags & UDP_FLG) {
            socks->udp_ipv4_socket = socket(AF_INET, SOCK_DGRAM, 0);
            CHECK_SOCKET(socks->udp_ipv4_socket);
        }
    }
    // ipv6 sockets
    if(scanner->parameter_flags & IPV6_FLG) {
        if(scanner->parameter_flags & TCP_FLG) {
            socks->tcp_ipv6_socket = socket(AF_INET6, SOCK_RAW, 0);
            CHECK_SOCKET(socks->tcp_ipv6_socket);
        }

        if(scanner->parameter_flags & UDP_FLG) {
            socks->udp_ipv6_socket = socket(AF_INET6, SOCK_DGRAM, 0);
            CHECK_SOCKET(socks->udp_ipv6_socket);
        }
    }
}


/**
 * @def     destroy_sockets
 * @brief   Closes all socket file descriptors that are active
 * @param   socks - Pointer to SocketsPtr struct which holds socket file descriptors
 * @return  nothing
 */
void destroy_sockets(SocketsPtr socks) {
    CLOSE_SOCKET(socks->tcp_ipv4_socket);
    CLOSE_SOCKET(socks->udp_ipv4_socket);
    CLOSE_SOCKET(socks->tcp_ipv6_socket);
    CLOSE_SOCKET(socks->udp_ipv6_socket);
}