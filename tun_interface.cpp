//
// Created by Brian Sandlin on 6/17/23.
//

#include "tun_interface.h"
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/sys_domain.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <cstring>
#include <unistd.h>
#include <fcntl.h>
#include <net/if.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <string>
#include <memory>
#include <array>

tun_address_pair::operator bool() const {
  return addr != 0u && dstaddr != 0u;
}

std::string to_string(const uint32_t &ip) {
  // convert IP address to string
  in_addr addr{};
  addr.s_addr = ip;

  char *ret = inet_ntoa(addr);
  if (ret == nullptr) {
    throw std::runtime_error("inet_ntoa failed");
  }
  return {ret, strnlen(ret, 16u)};
}

tun_interface::~tun_interface() {
  if (fd != -1) {
    close(fd);
  }
}

std::string tun_interface::device_name() const {
  if (fd == -1) {
    throw std::logic_error("device_name() called on invalid tun_interface");
  }

  std::array<char, IFNAMSIZ> ifname_buf{};
  socklen_t ifname_len = ifname_buf.size();
  int ret = getsockopt(fd, SYSPROTO_CONTROL, UTUN_OPT_IFNAME, ifname_buf.data(), &ifname_len);
  if (ret != 0) {
    throw std::runtime_error("getsockopt(UTUN_OPT_IFNAME) failed");
  }

  if (ifname_len >= ifname_buf.size()) {
    throw std::runtime_error("UTUN_OPT_IFNAME too long");
  }

  if (ifname_len <= 1) {
    throw std::runtime_error("UTUN_OPT_IFNAME empty");
  }

  return {ifname_buf.data(), ifname_len - 1};
}

tun_address_pair tun_interface::get_assigned_addresses() const {
  if (fd == -1) {
    throw std::logic_error("get_assigned_addresses() called on invalid tun_interface");
  }

  ifaddrs *ifaddr;
  if (getifaddrs(&ifaddr) == -1) {
    throw std::runtime_error("getifaddrs() failed");
  }
  using deleter = decltype([](ifaddrs *o) {
      freeifaddrs(o);
  });
  std::unique_ptr<ifaddrs, deleter> ifaddr_ptr(ifaddr);

  const std::string tun_name = device_name();
  for (ifaddrs *ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == nullptr || ifa->ifa_dstaddr == nullptr) {
      continue;
    }

    if (ifa->ifa_addr->sa_family != AF_INET && ifa->ifa_dstaddr->sa_family != AF_INET) {
      continue;
    }

    const std::string_view ifa_name(ifa->ifa_name, strnlen(ifa->ifa_name, IFNAMSIZ));

    if (ifa_name != tun_name) {
      continue;
    }

    auto *addr = reinterpret_cast<sockaddr_in *>(ifa->ifa_addr);
    uint32_t addr_l{addr->sin_addr.s_addr};
    auto *dstaddr = reinterpret_cast<sockaddr_in *>(ifa->ifa_dstaddr);
    uint32_t dstaddr_l{dstaddr->sin_addr.s_addr};
    return {
          .addr = addr_l,
          .dstaddr = dstaddr_l
    };
  }
  return {};
}

void tun_interface::set_nonblocking() const {
  if (fd == -1) {
    throw std::logic_error("set_nonblocking() called on invalid tun_interface");
  }

  int flags = fcntl(fd, F_GETFL, 0);
  if (flags == -1) {
    throw std::runtime_error("fcntl(F_GETFL) failed");
  }

  if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
    throw std::runtime_error("fcntl(F_SETFL) failed");
  }
}

void tun_interface::create() {
  fd = socket(PF_SYSTEM, SOCK_DGRAM, SYSPROTO_CONTROL);
  if (fd == -1) {
    throw std::runtime_error("socket(SYSPROTO_CONTROL) failed");
  }

  ctl_info ctlInfo{};
  size_t copied = strlcpy(ctlInfo.ctl_name,
                          UTUN_CONTROL_NAME,
                          std::size(ctlInfo.ctl_name));
  if (copied >= std::size(ctlInfo.ctl_name)) {
    throw std::runtime_error("UTUN_CONTROL_NAME too long");
  }

  if (ioctl(fd, CTLIOCGINFO, &ctlInfo) == -1) {
    throw std::runtime_error("ioctl(CTLIOCGINFO) failed");
  }

  sockaddr_ctl sc{
        .sc_len = sizeof(sc),
        .sc_family = AF_SYSTEM,
        .ss_sysaddr = AF_SYS_CONTROL,
        .sc_id = ctlInfo.ctl_id,
        .sc_unit = if_number
  };

  // If connect is successful, a create_tun_interface%d device will be created, where "%d"
  // is our unit number minus one

  if (connect(fd, (struct sockaddr *) &sc, sizeof(sc)) == -1) {
    throw std::runtime_error("connect(AF_SYS_CONTROL) failed");
  }
}
