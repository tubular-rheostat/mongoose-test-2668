//
// Created by Brian Sandlin on 3/30/24.
//

#ifndef MG_FD_NETIF_H
#define MG_FD_NETIF_H
#include "tun_interface.h"

// struct

struct mg_fd_netif_state
{
    int fd;
};

struct mg_tcpip_driver;
extern mg_tcpip_driver mg_fd_netif_tcpip;

#endif //MG_FD_NETIF_H
