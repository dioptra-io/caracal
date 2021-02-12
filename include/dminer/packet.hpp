#pragma once

#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <span>

namespace dminer {

class Packet {
 public:
  Packet(const std::span<std::byte> buffer, const uint8_t l3_protocol,
         const uint8_t l4_protocol, const size_t payload_size) {
    l3_protocol_ = l3_protocol;
    l4_protocol_ = l4_protocol;

    size_t l3_header_size;
    size_t l4_header_size;

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
        l4_header_size = sizeof(icmphdr);
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
    end_ = begin_ + l3_header_size + l4_header_size + payload_size;
    l3_ = begin_;
    l4_ = l3_ + l3_header_size;
    payload_ = l4_ + l4_header_size;
  }

  [[nodiscard]] std::byte *begin() const noexcept { return begin_; }

  [[nodiscard]] std::byte *end() const noexcept { return end_; }

  [[nodiscard]] std::byte *l3() const noexcept { return l3_; }

  [[nodiscard]] std::byte *l4() const noexcept { return l4_; }

  [[nodiscard]] std::byte *payload() const noexcept { return payload_; }

  // Size of L3 header + L3 payload.
  [[nodiscard]] size_t l3_size() const noexcept { return end_ - l3_; }

  [[nodiscard]] size_t l4_size() const noexcept { return end_ - l4_; }

  [[nodiscard]] size_t payload_size() const noexcept { return end_ - payload_; }

  [[nodiscard]] uint8_t l3_protocol() const noexcept { return l3_protocol_; }

  [[nodiscard]] uint8_t l4_protocol() const noexcept { return l4_protocol_; }

 private:
  std::byte *begin_;
  std::byte *end_;
  std::byte *l3_;
  std::byte *l4_;
  std::byte *payload_;
  uint8_t l3_protocol_;
  uint8_t l4_protocol_;
};

}  // namespace dminer
