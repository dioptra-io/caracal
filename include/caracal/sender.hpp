#pragma once

#include <net/ethernet.h>
#include <netinet/ip.h>
#ifdef __APPLE__
#include <net/if.h>
#include <net/ndrv.h>
#elif __linux__
#include <linux/if_packet.h>
#endif
#include <tins/tins.h>

#include <array>
#include <string>

#include "probe.hpp"
#include "socket.hpp"

namespace caracal {

class Sender {
 public:
  // batch_size has no effect on macOS.
  Sender(const Tins::NetworkInterface &interface, const std::string &protocol,
         uint32_t batch_size);
  ~Sender();
  void flush();
  bool send(const Probe &probe);

 private:
  uint8_t l2_protocol_;
  uint8_t l4_protocol_;
  Socket socket_;
#ifdef __APPLE__
  std::array<std::byte, 1024> buffer_;
  sockaddr_ndrv if_;
#elif __linux__
  void *ring_;
  uint32_t frame_count_;
  uint32_t frame_size_;
  uint32_t frame_idx_;
  sockaddr_ll if_;
#endif
  std::array<uint8_t, ETHER_ADDR_LEN> src_mac_;
  std::array<uint8_t, ETHER_ADDR_LEN> dst_mac_;
  sockaddr_in src_ip_v4;
  sockaddr_in6 src_ip_v6;
};
}  // namespace caracal
