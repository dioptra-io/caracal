#pragma once

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <pcap/pcap.h>

#include <array>
#include <string>

#include "./probe.hpp"

namespace caracal {

class Sender {
 public:
  explicit Sender(const std::string &interface_name, uint16_t caracal_id);

  ~Sender();

  void send(const Probe &probe);

 private:
  std::array<std::byte, 65536> buffer_;
  Protocols::L2 l2_protocol_;
  std::array<uint8_t, ETHER_ADDR_LEN> src_mac_;
  std::array<uint8_t, ETHER_ADDR_LEN> dst_mac_;
  sockaddr_in src_ip_v4_;
  sockaddr_in6 src_ip_v6_;
  uint16_t caracal_id_;
  pcap_t *handle_;
};
}  // namespace caracal
