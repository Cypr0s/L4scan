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
        // create ipv4 bind address
        struct sockaddr_in socket_interface = {0};
        if(inet_pton(AF_INET, scanner->interface_ipv4, &(socket_interface.sin_addr)) == -1) {
            perror("inet_pton");
            return ERR_FAILURE;
        }

        socket_interface.sin_family = AF_INET;
        socket_interface.sin_port = 0;

        if(scanner->parameter_flags & TCP_FLG) {
            socks->tcp_ipv4_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
            if(socks->tcp_ipv4_socket == -1) {              
                perror("socket");
                return ERR_SOCKET;
            }   
            if(bind(socks->tcp_ipv4_socket,(struct sockaddr*) &socket_interface, sizeof(socket_interface))) {
                perror("bind");
                return ERR_SOCKET;
            }
        }

        if(scanner->parameter_flags & UDP_FLG) {
            socks->udp_ipv4_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if(socks->udp_ipv4_socket == -1) {              
                perror("socket");
                return ERR_SOCKET;
            }

            if(bind(socks->udp_ipv4_socket,(struct sockaddr*) &socket_interface, sizeof(socket_interface))) {
                perror("bind");
                return ERR_SOCKET;
            }
        }

    }
    // ipv6 sockets
    if(scanner->parameter_flags & IPV6_FLG) {

        struct sockaddr_in6 socket_interface = {0};
        if(inet_pton(AF_INET6, scanner->interface_ipv4, &(socket_interface.sin6_addr)) == -1){
            perror("inet_pton");
            return ERR_FAILURE;
        }

        socket_interface.sin6_family = AF_INET6;
        socket_interface.sin6_port = 0;

        if(scanner->parameter_flags & TCP_FLG) {
            socks->tcp_ipv6_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
            if(socks->tcp_ipv6_socket == -1) {              
                perror("socket");
                return ERR_SOCKET;
            }   
            if(bind(socks->tcp_ipv6_socket, (struct sockaddr*) &socket_interface, sizeof(socket_interface))) {
                perror("bind");
                return ERR_SOCKET;
            }
        }

        if(scanner->parameter_flags & UDP_FLG) {
            socks->udp_ipv6_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            if(socks->udp_ipv6_socket == -1) {              
                perror("socket");
                return ERR_SOCKET;
            }   
            if(bind(socks->udp_ipv6_socket,(struct sockaddr*) &socket_interface, sizeof(socket_interface))) {
                perror("bind");
                return ERR_SOCKET;
            }
        }
    }
    return ERR_SUCCESS;
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