#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

#include <dminer/constants.hpp>
#include <dminer/packet.hpp>
#include <span>
#include <stdexcept>

namespace dminer {

Packet::Packet(const std::span<std::byte> buffer, const uint8_t l2_protocol,
               const uint8_t l3_protocol, const uint8_t l4_protocol,
               const size_t payload_size) {
  l2_protocol_ = l2_protocol;
  l3_protocol_ = l3_protocol;
  l4_protocol_ = l4_protocol;

  size_t l2_header_size;
  size_t l3_header_size;
  size_t l4_header_size;

  // Pad the beginning of the packet to align on a four-byte boundary.
  // See https://lwn.net/Articles/89597/.
  size_t padding;

  switch (l2_protocol) {
    case L2PROTO_BSDLOOPBACK:
      l2_header_size = sizeof(uint32_t);
      padding = 0;
      break;

    case L2PROTO_ETHERNET:
      l2_header_size = sizeof(ether_header);
      padding = 2;
      break;

    case L2PROTO_NONE:
      l2_header_size = 0;
      padding = 0;
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

  begin_ = buffer.data();
  l2_ = begin_ + padding;
  l3_ = l2_ + l2_header_size;
  l4_ = l3_ + l3_header_size;
  payload_ = l4_ + l4_header_size;
  end_ = payload_ + payload_size;

  if (buffer.size() < static_cast<uint64_t>(end_ - begin_)) {
    throw std::invalid_argument{"Packet buffer is too small"};
  }
}

std::byte* Packet::begin() const noexcept { return begin_; }

std::byte* Packet::end() const noexcept { return end_; }

std::byte* Packet::l2() const noexcept { return l2_; }

std::byte* Packet::l3() const noexcept { return l3_; }

std::byte* Packet::l4() const noexcept { return l4_; }

std::byte* Packet::payload() const noexcept { return payload_; }

size_t Packet::l2_size() const noexcept { return end_ - l2_; }

size_t Packet::l3_size() const noexcept { return end_ - l3_; }

size_t Packet::l4_size() const noexcept { return end_ - l4_; }

size_t Packet::payload_size() const noexcept { return end_ - payload_; }

uint8_t Packet::l2_protocol() const noexcept { return l2_protocol_; }

uint8_t Packet::l3_protocol() const noexcept { return l3_protocol_; }

uint8_t Packet::l4_protocol() const noexcept { return l4_protocol_; }

}  // namespace dminer
