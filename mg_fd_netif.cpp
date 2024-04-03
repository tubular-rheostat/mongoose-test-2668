//
// Created by Brian Sandlin on 3/30/24.
//

#include <array>
#include <algorithm>
#include "mongoose.h"
#include "mg_fd_netif.h"
#include "tun_interface.h"

using std::array, std::data, std::size;

constexpr size_t TUN_MTU = 1500;

namespace proto
{
    // structures copied out of mongoose net_builtin.c
    //
    // > The world is a jungle in general, and the networking game
    // contributes many animals.
    //
    // from the introduction to *RFC 826*

#pragma pack(push, 1)

    // Ethernet MAC header
    struct eth {
        uint8_t dst[6];  // Destination MAC address
        uint8_t src[6];  // Source MAC address
        uint16_t type;   // Ethernet type
    };
    static_assert(sizeof(eth) == 14);

    // IP ARP header (RFC 826)
    struct arp {
        uint16_t fmt;    // Format of hardware address
        uint16_t pro;    // Format of protocol address
        uint8_t hlen;    // Length of hardware address
        uint8_t plen;    // Length of protocol address
        uint16_t op;     // Operation
        uint8_t sha[6];  // Sender hardware address
        uint32_t spa;    // Sender protocol address
        uint8_t tha[6];  // Target hardware address
        uint32_t tpa;    // Target protocol address
    };

    static_assert(sizeof(arp) == 28);
#pragma pack(pop)
}

static bool mg_fd_netif_init([[maybe_unused]] mg_tcpip_if* intf)
{
    MG_DEBUG(("tun init"));
    return true;
}

static bool mg_fd_netif_link_status([[maybe_unused]] mg_tcpip_if* intf)
{
    return true;
}

static array<uint8_t, sizeof(proto::arp)> pending_arp_reply_buf{};
static bool has_pending_arp_reply{};

static size_t mg_fd_netif_transmit(const void* data, size_t len, mg_tcpip_if* intf)
{
    if (len < sizeof(proto::eth))
    {
        MG_DEBUG(("discarding, too short"));
        return 0;
    }
    auto s = static_cast<mg_fd_netif_state*>(intf->driver_data);
    array<uint8_t, TUN_MTU + 4u> output_buf{};
    output_buf[0] = 0u;
    output_buf[1] = 0u;
    output_buf[2] = 0u;
    output_buf[3] = AF_INET;

    auto input_buf = static_cast<const uint8_t*>(data);
    auto frame = reinterpret_cast<const proto::eth*>(input_buf);

    if(frame->type == htons(0x0806))
    {
        // ARP; prepare to reply
        if(len < sizeof(proto::eth) + sizeof(proto::arp))
        {
            MG_DEBUG(("discarding, too short"));
            return 0;
        }
        auto *arp_request = reinterpret_cast<const proto::arp *>(input_buf + sizeof(proto::eth));
        if(ntohs(arp_request->op) == 2u)
        {
            // ignore reply
            return len;
        }
        auto *arp_reply = reinterpret_cast<proto::arp *>(std::data(pending_arp_reply_buf));
        *arp_reply = {
            .fmt = htons(1),
            .pro = htons(0x0800),
            .hlen = 6,
            .plen = 4,
            .op = htons(2),
            .sha = {intf->mac[0], intf->mac[1], intf->mac[2], intf->mac[3], intf->mac[4], intf->mac[5]},
            .spa = htonl(0x01000001),
            .tha = {frame->src[0], frame->src[1], frame->src[2], frame->src[3], frame->src[4], frame->src[5]},
            .tpa = arp_request->spa
        };
        has_pending_arp_reply = true;
        MG_DEBUG(("arp"));
        return len;
    }

    if(frame->type != htons(0x0800))
    {
        MG_DEBUG(("discarding, unknown ethertype 0x%04x", frame->type));
        return len;
    }

    size_t bytes_to_copy = std::min(len - sizeof(proto::eth), TUN_MTU);
    assert(bytes_to_copy == len - sizeof(proto::eth));
    std::copy_n(input_buf + sizeof(proto::eth), bytes_to_copy, std::data(output_buf) + 4u);
    MG_DEBUG(("tun transmit %u bytes", bytes_to_copy + 4u));
    ssize_t write_ret = write(s->fd, std::data(output_buf), bytes_to_copy + 4u);
    if(write_ret < 0)
    {
        MG_DEBUG(("write failed"));
        return 0;
    }
    auto write_len = static_cast<size_t>(write_ret);
    if(write_len != bytes_to_copy + 4u)
    {
        MG_DEBUG(("write failed"));
    }
    return bytes_to_copy;
}

static size_t mg_fd_netif_receive(void* buf, size_t len, mg_tcpip_if* intf)
{
    auto s = static_cast<mg_fd_netif_state*>(intf->driver_data);
    array<uint8_t, TUN_MTU + 4u> read_buf{};
    ssize_t read_ret{};
    if (has_pending_arp_reply)
    {
        // ARP simulate a reply
        if (len < size(pending_arp_reply_buf) + 4u)
        {
            MG_DEBUG(("discarding, too short"));
            return len;
        }
        std::copy_n(data(pending_arp_reply_buf), size(pending_arp_reply_buf), data(read_buf) + 4);
        has_pending_arp_reply = false;
        MG_DEBUG(("arp reply"));
        read_buf[0] = 0u;
        read_buf[1] = 0u;
        read_buf[2] = 0u;
        read_buf[3] = AF_INET;
        read_ret = size(pending_arp_reply_buf) + 4;
    }
    else
    {
        read_ret = read(s->fd, data(read_buf), size(read_buf));
    }
    const int error = errno;
    if (read_ret < 0)
    {
        if (error == EAGAIN)
        {
            // no data available
            return 0;
        }
        MG_DEBUG(("read failed"));
        return 0;
    }
    if(read_ret < 4)
    {
        MG_DEBUG(("short read"));
        return 0;
    }
    MG_DEBUG(("tun receive %d bytes", read_ret - 4));
    int af = read_buf[3];
    if(af != AF_INET)
    {
        MG_DEBUG(("discarding, unknown AF %d", af));
        return 0;
    }
    auto output_buf = static_cast<uint8_t*>(buf);
    // assert if output_buf is not aligned on a 2 byte boundary
    assert(reinterpret_cast<uintptr_t>(output_buf) & 0x01u == 0x00u);

    proto::eth *frame = reinterpret_cast<proto::eth *>(output_buf);
    *frame = {
        .dst = {intf->mac[0], intf->mac[1], intf->mac[2], intf->mac[3], intf->mac[4], intf->mac[5]},
        .src = {0x02u, 0x32u, 0x64u, 0x00u, 0x00u, 0x01u},
        .type = htons(0x0800u)
    };

    size_t bytes_to_copy = std::min(static_cast<size_t>(read_ret - 4), len - sizeof(proto::eth));
    assert(bytes_to_copy == read_ret - 4);
    std::copy_n(data(read_buf) + 4, bytes_to_copy, output_buf + sizeof(proto::eth));
    return bytes_to_copy + sizeof(proto::eth);
}

mg_tcpip_driver mg_fd_netif_tcpip = {
    mg_fd_netif_init,
    mg_fd_netif_transmit,
    mg_fd_netif_receive,
    mg_fd_netif_link_status
};
