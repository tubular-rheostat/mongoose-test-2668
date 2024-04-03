//
// Created by Brian Sandlin on 6/17/23.
//

#ifndef NET_CLIENT_TUN_INTERFACE_H
#define NET_CLIENT_TUN_INTERFACE_H

#include <string>


// Driver to create a macOS `tun` interface.
struct tun_address_pair {
  uint32_t addr;
  uint32_t dstaddr;

  explicit operator bool() const;
};

[[nodiscard]] std::string to_string(const uint32_t &addr);

class tun_interface final {
  int fd;
  uint32_t if_number;

public:

  explicit tun_interface(uint32_t if_number) noexcept: fd(-1), if_number(if_number) {}

  ~tun_interface();

  [[nodiscard]] int get_fd() const {
    return fd;
  }

  void create();

  [[nodiscard]] std::string device_name() const;

  [[nodiscard]] tun_address_pair get_assigned_addresses() const;

  void set_nonblocking() const;
};

#endif //NET_CLIENT_TUN_INTERFACE_H
