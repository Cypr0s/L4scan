/** -------------- L4scan -----------------
 * @file    sockets.c
 * @author  Kristian Luptak <xluptak00>
 * @date    creation:   15.3.2026
 *          updated:    22.3.2026
 * @brief   File handles anything related to sockets, like creating 
 *          them and destroying them        
 */


#include "sockets.h"


/**
 * @def     init_sockets
 * @brief   init sockets to their default value (so we dont try to free non existent socket)
 * @param   socks - pointer to sockets struct
 * @return  nothing
 */
void init_sockets_struct(SocketsPtr socks) {
    socks->tcp_ipv4_socket = -1;
    socks->tcp_ipv6_socket = -1;
    socks->udp_ipv4_socket = -1;
    socks->udp_ipv6_socket = -1;
}


/**
 * @def     create_sockets
 * @brief   Create 4 different types of socket based on input from scanner struct, 
 *          assume caller frees allocated socket file descriptors
 * @param   scanner - pointer to scanner struct which holds information about which 
 *                    sockets to create inside scanner->parameter_flags
 * @param   socks - pointer to Sockets 
 */
ExitEnum create_sockets(SocketsPtr socks, ScannerPtr scanner) {
    //ipv4 sockets
    if(scanner->parameter_flags & IPV4_FLG) {
        // tcp socket
        if(scanner->parameter_flags & TCP_FLG) {
            socks->tcp_ipv4_socket = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
            if(socks->tcp_ipv4_socket == -1) {              
                perror("socket");
                return ERR_SOCKET;
            }
        }
        // udp socket
        if(scanner->parameter_flags & UDP_FLG) {
            socks->udp_ipv4_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if(socks->udp_ipv4_socket == -1) {              
                perror("socket");
                return ERR_SOCKET;
            }
        }

    }
    // ipv6 sockets
    if(scanner->parameter_flags & IPV6_FLG) {
        // tcp socket
        if(scanner->parameter_flags & TCP_FLG) {
            socks->tcp_ipv6_socket = socket(AF_INET6, SOCK_RAW, IPPROTO_TCP);
            if(socks->tcp_ipv6_socket == -1) {              
                perror("socket");
                return ERR_SOCKET;
            }
        }

        // udp socket
        if(scanner->parameter_flags & UDP_FLG) {
            socks->udp_ipv6_socket = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
            if(socks->udp_ipv6_socket == -1) {              
                perror("socket");
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


/** 
 * @def     bind_sockets
 * @brief   binds udp sockets to correct interfaces, sets needed options for tcp sockets
 * @param   socks - struct which holds all open sockets
 * @param   scanner - holds interface ipv4 and ipv6 wich will be used for binding
 * @return  ERR_SUCCESS(0)  no errors
 *          ERR_SOCKET(5)   bind or setsockopt error
 */
ExitEnum bind_sockets(SocketsPtr socks, ScannerPtr scanner) {
    // bind udp_ipv4 socket to interface ipv4
    if(socks->udp_ipv4_socket != -1) {
        // create ipv4 bind address
        struct sockaddr_in socket_interface = {0};

        socket_interface.sin_addr = scanner->interface_ipv4; 
        socket_interface.sin_family = AF_INET;
        socket_interface.sin_port = htons(SOURCE_PORT);

        // bind socket to address
        if(bind(socks->udp_ipv4_socket,
                (struct sockaddr*) &socket_interface, 
                sizeof(socket_interface))) 
        {
            perror("bind");
            return ERR_SOCKET;
        }
    }
    // set that we will provide our own ipv4 + tcp header
    if(socks->tcp_ipv4_socket != -1) {
        int flag = 1;
        if(setsockopt(socks->tcp_ipv4_socket, IPPROTO_IP, IP_HDRINCL, &flag, sizeof(flag)) < 0) {
            perror("setsockopt");
            return ERR_SOCKET;
        }
    }
    // bind udp socket to correct ipv6 interface
    if(socks->udp_ipv6_socket != -1) {
        // create ipv6 bind address
        struct sockaddr_in6 socket_interface = {0};
        
        socket_interface.sin6_addr = scanner->interface_ipv6;
        socket_interface.sin6_family = AF_INET6;
        socket_interface.sin6_port = htons(SOURCE_PORT);

        // bind socket to address
        if(bind(socks->udp_ipv6_socket,
                (struct sockaddr*) &socket_interface, 
                sizeof(socket_interface))) 
        {
            perror("bind");
            return ERR_SOCKET;
        }
    }

    // set that we will provide tcp header but no ipv6
    if(socks->tcp_ipv6_socket != -1) {
        int offset = 16; // kernel calculates ipv6 checksum but tcp header will be needed
        if(setsockopt(socks->tcp_ipv6_socket, 
                        IPPROTO_IPV6, IPV6_CHECKSUM, &offset, sizeof(offset)) < 0) {
            perror("setsockop");
            return ERR_SOCKET;
        }
    }
    return ERR_SUCCESS;
} // bind_sockets