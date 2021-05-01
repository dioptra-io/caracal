#pragma once

#include <net/ethernet.h>
#include <netinet/ip.h>
#ifdef __APPLE__
#include <net/if.h>
#include <net/ndrv.h>
#elif __linux__
#include <netpacket/packet.h>
#endif

#include <array>
#include <string>

#include "probe.hpp"
#include "socket.hpp"

namespace caracal {

class Sender {
 public:
  explicit Sender(const std::string &interface_name, uint16_t caracal_id);

  void send(const Probe &probe);

 private:
  std::array<std::byte, 65536> buffer_;
  Protocols::L2 l2_protocol_;
  Socket socket_;
#ifdef __APPLE__
  sockaddr_ndrv if_;
#elif __linux__
  sockaddr_ll if_;
#endif
  std::array<uint8_t, ETHER_ADDR_LEN> src_mac_;
  std::array<uint8_t, ETHER_ADDR_LEN> dst_mac_;
  sockaddr_in src_ip_v4_;
  sockaddr_in6 src_ip_v6_;
  uint16_t caracal_id_;
};
}  // namespace caracal
