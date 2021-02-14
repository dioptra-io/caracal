#pragma once

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <span>

#include "constants.hpp"

namespace dminer {

/// A structure holding pointers to the different layers of a packet buffer.
class Packet {
 public:
  Packet(const std::span<std::byte> buffer, const uint8_t l2_protocol,
         const uint8_t l3_protocol, const uint8_t l4_protocol,
         const size_t payload_size) {
    l2_protocol_ = l2_protocol;
    l3_protocol_ = l3_protocol;
    l4_protocol_ = l4_protocol;

    size_t l2_header_size;
    size_t l3_header_size;
    size_t l4_header_size;

    switch (l2_protocol) {
      case L2PROTO_BSDLOOPBACK:
        l2_header_size = sizeof(uint32_t);
        break;

      case L2PROTO_ETHERNET:
        l2_header_size = sizeof(ether_header);
        break;

      case L2PROTO_NONE:
        l2_header_size = 0;
        break;

      default:
        throw std::invalid_argument{"Unsupported L2 protocol"};
    }

    switch (l3_protocol) {
      case IPPROTO_IP:
        l3_header_size = sizeof(ip);
        break;

      case IPPROTO_IPV6:
        l3_header_size = sizeof(ip6_hdr);
        break;

      default:
        throw std::invalid_argument{"Unsupported L3 protocol"};
    }

    switch (l4_protocol) {
      case IPPROTO_ICMP:
        l4_header_size = ICMP_HEADER_SIZE;
        break;

      case IPPROTO_TCP:
        l4_header_size = sizeof(tcphdr);
        break;

      case IPPROTO_UDP:
        l4_header_size = sizeof(udphdr);
        break;

      default:
        throw std::invalid_argument{"Unsupported L4 protocol"};
    }

    if (buffer.size() < (l3_header_size + l4_header_size + payload_size)) {
      throw std::invalid_argument{"Packet buffer is too small"};
    }

    begin_ = buffer.data();
    l2_ = begin_;
    l3_ = l2_ + l2_header_size;
    l4_ = l3_ + l3_header_size;
    payload_ = l4_ + l4_header_size;
    end_ = payload_ + payload_size;
  }

  /// A pointer to the first byte of the packet.
  [[nodiscard]] std::byte *begin() const noexcept { return begin_; }

  /// A pointer past the last byte of the packet.
  [[nodiscard]] std::byte *end() const noexcept { return end_; }

  /// A pointer to the first byte of the layer 2.
  [[nodiscard]] std::byte *l2() const noexcept { return l2_; }

  /// A pointer to the first byte of the layer 3.
  [[nodiscard]] std::byte *l3() const noexcept { return l3_; }

  /// A pointer to the first byte if the layer 4.
  [[nodiscard]] std::byte *l4() const noexcept { return l4_; }

  /// A pointer to the first byte of the payload.
  [[nodiscard]] std::byte *payload() const noexcept { return payload_; }

  /// Size of the packet starting from the L2 header.
  [[nodiscard]] size_t l2_size() const noexcept { return end_ - l2_; }

  /// Size of the packet starting from the L3 header.
  [[nodiscard]] size_t l3_size() const noexcept { return end_ - l3_; }

  /// Size of the packet starting from the L4 header.
  [[nodiscard]] size_t l4_size() const noexcept { return end_ - l4_; }

  /// Size of the packet starting from the payload.
  [[nodiscard]] size_t payload_size() const noexcept { return end_ - payload_; }

  /// Layer 2 protocol.
  [[nodiscard]] uint8_t l2_protocol() const noexcept { return l2_protocol_; }

  /// Layer 3 protocol.
  [[nodiscard]] uint8_t l3_protocol() const noexcept { return l3_protocol_; }

  /// Layer 4 protocol.
  [[nodiscard]] uint8_t l4_protocol() const noexcept { return l4_protocol_; }

 private:
  std::byte *begin_;
  std::byte *end_;
  std::byte *l2_;
  std::byte *l3_;
  std::byte *l4_;
  std::byte *payload_;
  uint8_t l2_protocol_;
  uint8_t l3_protocol_;
  uint8_t l4_protocol_;
};

}  // namespace dminer
